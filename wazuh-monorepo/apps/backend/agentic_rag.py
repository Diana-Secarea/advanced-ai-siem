"""Phase-1 agentic RAG stages for the chat pipeline.

Three LLM-driven retrieval decisions, each a single small completion with a
strict one-line output format:

  1. gate_skip()       — does this message need retrieval at all?
  2. rewrite_queries() — reformulate the question into up to 3 search queries
  3. grade_chunks()    — CRAG-style relevance grading of retrieved chunks

Every stage fails open: an unreachable LLM, a timeout, or unparseable output
degrades to the legacy one-shot behaviour (retrieve, original query only,
keep every chunk) — the chat never breaks because a helper call misbehaved.

The `llm` argument is a callable(messages, max_tokens=N) -> str supplied by
the server (a temperature-0 Ollama completion with a short timeout). Error
strings from that callable start with "Error" and never match any expected
format, so they fall through to the safe default automatically.
"""

import re

MAX_QUERIES = 3          # rewrites added on top of the original message
HISTORY_TAIL = 4         # conversation turns shown to the helper calls
HISTORY_CLIP = 200       # chars per turn — keeps helper prompts tiny

_GATE_SYSTEM = (
    "You decide whether a message sent to a security-analyst assistant needs "
    "a search of Wazuh alert logs and threat-intelligence documents before "
    "it can be answered.\n"
    "Reply with exactly one word.\n"
    "SKIP — greetings, thanks, small talk, or requests purely about the "
    "assistant's previous answer (rephrase it, translate it, shorten it, "
    "explain a term it used).\n"
    "RETRIEVE — anything mentioning alerts, logs, attacks, agents, CVEs, "
    "techniques, rules, or any question that needs facts about the system "
    "or about security. If unsure, reply RETRIEVE."
)

_REWRITE_SYSTEM = (
    "You write search queries for a cybersecurity knowledge base (MITRE "
    "ATT&CK techniques, YARA rules, vendor advisories) and a Wazuh alert "
    "log index.\n"
    "Rewrite the user's question into up to 3 short keyword queries that "
    "together cover it. Every query must stay strictly on the question's "
    "own topic: expand acronyms the question uses, add synonyms of the "
    "question's own terms, and name the concrete techniques, tools, or log "
    "artifacts it involves. Never introduce attack types or topics the "
    "question does not mention. Resolve pronouns like \"it\" or \"that "
    "alert\" from the conversation.\n"
    "Output ONLY the queries, one per line, no numbering, no commentary."
)

_GRADE_SYSTEM = (
    "You grade whether retrieved reference chunks are relevant to a user's "
    "question. A chunk is relevant if it helps answer the question, even "
    "partially.\n"
    "Reply with exactly one line: KEEP: followed by the comma-separated "
    "numbers of the relevant chunks, or KEEP: none if none are relevant."
)


def _history_tail(history):
    """Last few turns, clipped hard — enough for pronoun resolution."""
    return [{"role": m["role"], "content": (m.get("content") or "")[:HISTORY_CLIP]}
            for m in history[-HISTORY_TAIL:]
            if m.get("role") in ("user", "assistant")]


def gate_skip(llm, user_message, history):
    """True only when the LLM confidently says no retrieval is needed."""
    msgs = [{"role": "system", "content": _GATE_SYSTEM}]
    msgs += _history_tail(history)
    msgs.append({"role": "user", "content": user_message})
    out = (llm(msgs, max_tokens=4) or "").strip().upper()
    return out.startswith("SKIP")


def rewrite_queries(llm, user_message, history, feedback=None):
    """Expand the question into search queries; the original always comes first.

    feedback: terms already tried that found nothing relevant — set on the
    corrective retry so the model picks different vocabulary.
    """
    msgs = [{"role": "system", "content": _REWRITE_SYSTEM}]
    msgs += _history_tail(history)
    prompt = user_message
    if feedback:
        prompt += (f"\n\n(These queries found nothing relevant: {feedback}. "
                   "Use different terms.)")
    msgs.append({"role": "user", "content": prompt})

    out = llm(msgs, max_tokens=120) or ""
    queries = [user_message]
    if out.strip().lower().startswith("error"):
        return queries
    for line in out.splitlines():
        q = re.sub(r"^[\s\-\*\d.)]+", "", line).strip().strip('"')
        if 2 < len(q) <= 200 and q.lower() != user_message.lower() and q not in queries:
            queries.append(q)
        if len(queries) > MAX_QUERIES:
            break
    return queries


def grade_chunks(llm, user_message, chunks):
    """Return (kept_indices, graded) for the given chunk texts.

    graded False means the grader's output was unusable and every chunk was
    kept unfiltered; ([], True) means it confidently judged all irrelevant —
    the caller's cue for a corrective re-retrieve.
    """
    if not chunks:
        return [], True
    listing = "\n".join(f"[{i}] {c[:400]}" for i, c in enumerate(chunks, 1))
    msgs = [
        {"role": "system", "content": _GRADE_SYSTEM},
        {"role": "user", "content": f"Question: {user_message}\n\nChunks:\n{listing}"},
    ]
    out = (llm(msgs, max_tokens=32) or "").strip()

    m = re.search(r"KEEP:\s*(.*)", out, re.IGNORECASE)
    if not m:
        return list(range(len(chunks))), False
    body = m.group(1).strip()
    if body.lower().startswith("none"):
        return [], True
    kept = sorted({int(n) - 1 for n in re.findall(r"\d+", body)
                   if 0 < int(n) <= len(chunks)})
    if not kept:
        return list(range(len(chunks))), False
    return kept, True
