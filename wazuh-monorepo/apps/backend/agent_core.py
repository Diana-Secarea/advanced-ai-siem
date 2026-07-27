"""Hand-rolled bounded agent loop over Ollama's native chat + tools API.

No framework: one state machine that lets the model call read-only tools to
gather evidence, under a hard budget. The caller supplies the tools and
decides what to do with the evidence (stream an answer, write a triage
report); this module never talks to the rest of the backend.

Guardrails baked into the loop itself:
  - hard budget: at most `max_tool_calls` executed calls AND a wall-clock
    cap — whichever hits first ends the loop and the caller answers with
    whatever evidence exists;
  - every tool argument set is validated before execution; invalid or
    unknown calls consume budget (so a confused model cannot spin forever)
    and the error is fed back as the tool result;
  - repeated identical calls are refused;
  - tool output is truncated and passed through the caller's `sanitize`
    hook (delimiter defanging) before the model sees it;
  - tools are whatever the caller registers — this module executes nothing
    but the registered callables.
"""

import json
import time


class AgentUnsupported(Exception):
    """The model / Ollama build cannot do tool calling — caller should fall back."""


class AgentTool:
    """One read-only capability the model may invoke.

    fn(**args) -> str. validate(args) -> error string or None. Output is
    truncated to max_chars before entering the transcript.
    """

    def __init__(self, name, description, parameters, fn,
                 validate=None, max_chars=4000):
        self.name = name
        self.description = description
        self.parameters = parameters      # JSON schema for the arguments
        self.fn = fn
        self.validate = validate
        self.max_chars = max_chars

    def schema(self):
        return {"type": "function",
                "function": {"name": self.name,
                             "description": self.description,
                             "parameters": self.parameters}}


def _chat(ollama_url, model, messages, tools=None, timeout=45, fmt=None,
          num_predict=512):
    """One non-streaming native /api/chat call; returns the message dict."""
    import requests

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": num_predict},
        "keep_alive": "24h",
    }
    if tools:
        payload["tools"] = tools
    if fmt:
        payload["format"] = fmt
    resp = requests.post(f"{ollama_url}/api/chat", json=payload, timeout=timeout)
    if resp.status_code == 400 and tools:
        # Ollama answers 400 when the model has no tool-call template.
        raise AgentUnsupported(resp.text[:200])
    resp.raise_for_status()
    return resp.json().get("message", {}) or {}


def _coerce_scalar(v):
    """Small local models sometimes emit {'type':'string','description':'x'} or
    {'value':'x'} instead of the bare value — unwrap the obvious cases."""
    if isinstance(v, dict):
        for key in ("value", "query", "description"):
            if isinstance(v.get(key), (str, int, float)):
                return v[key]
    return v


def _parse_args(raw):
    if not isinstance(raw, dict):
        try:
            raw = json.loads(raw or "{}")
        except (TypeError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
    return {k: _coerce_scalar(v) for k, v in raw.items()}


def run_agent(ollama_url, model, system_prompt, question, tools,
              max_tool_calls=3, per_call_timeout=45, wall_budget_s=90,
              on_event=None, sanitize=None):
    """Iterate: model picks a tool → execute → feed result back → repeat.

    Stops when the model answers without a tool call, the call budget is
    spent, or the wall clock runs out. Raises AgentUnsupported if the model
    cannot tool-call at all (first round only — callers fall back cleanly).

    Returns {"evidence": [{tool, args, output, ok}], "stop_reason",
             "steps", "elapsed_ms"}.
    """
    tool_map = {t.name: t for t in tools}
    schemas = [t.schema() for t in tools]
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": question}]
    evidence = []
    seen_calls = set()
    calls = 0
    t0 = time.time()
    stop_reason = "answer_ready"

    # A round = one model turn; a turn may request several calls. Bound the
    # rounds too so unknown-tool loops (which consume budget anyway) can't
    # run long even in pathological cases.
    for _round in range(max_tool_calls + 2):
        if calls >= max_tool_calls:
            stop_reason = "call_budget"
            break
        if time.time() - t0 > wall_budget_s:
            stop_reason = "time_budget"
            break
        try:
            msg = _chat(ollama_url, model, messages, tools=schemas,
                        timeout=per_call_timeout)
        except AgentUnsupported:
            if calls == 0:
                raise               # nothing gathered — let the caller fall back
            stop_reason = "error"   # mid-run glitch: answer from what we have
            break
        except Exception as e:
            stop_reason = "error" if calls else f"error: {str(e)[:120]}"
            break

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            stop_reason = "answer_ready"
            break

        messages.append(msg)        # keep the assistant turn that asked
        for tc in tool_calls:
            fn_spec = tc.get("function") or {}
            name = str(fn_spec.get("name", ""))[:64]
            args = _parse_args(fn_spec.get("arguments"))
            if calls >= max_tool_calls:
                messages.append({"role": "tool", "tool_name": name,
                                 "content": "tool budget exhausted — answer now "
                                            "from the evidence above"})
                continue
            calls += 1
            call_key = name + "|" + json.dumps(args, sort_keys=True)
            tool = tool_map.get(name)

            if tool is None:
                ok, output = False, (f"unknown tool '{name}' — available: "
                                     + ", ".join(sorted(tool_map)))
            elif call_key in seen_calls:
                ok, output = False, ("already called with these exact arguments — "
                                     "use the earlier result or answer now")
            else:
                seen_calls.add(call_key)
                err = tool.validate(args) if tool.validate else None
                if err:
                    ok, output = False, f"invalid arguments: {err}"
                else:
                    try:
                        output, ok = str(tool.fn(**args)), True
                    except Exception as e:
                        ok, output = False, f"tool failed: {str(e)[:200]}"

            limit = tool.max_chars if tool else 400
            output = output[:limit]
            if ok and sanitize:
                output = sanitize(output)
            if on_event:
                try:
                    on_event({"step": calls, "tool": name, "args": args, "ok": ok})
                except Exception:
                    pass
            evidence.append({"tool": name, "args": args, "output": output, "ok": ok})
            messages.append({"role": "tool", "tool_name": name, "content": output})
    else:
        stop_reason = "round_budget"

    return {"evidence": evidence, "stop_reason": stop_reason,
            "steps": calls, "elapsed_ms": int((time.time() - t0) * 1000)}


def chat_json(ollama_url, model, system_prompt, user_prompt,
              timeout=90, num_predict=768):
    """One structured-output call (Ollama JSON mode). None if unparseable."""
    msg = _chat(ollama_url, model,
                [{"role": "system", "content": system_prompt},
                 {"role": "user", "content": user_prompt}],
                timeout=timeout, fmt="json", num_predict=num_predict)
    try:
        parsed = json.loads(msg.get("content") or "")
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        return None
