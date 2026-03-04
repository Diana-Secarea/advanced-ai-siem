#!/usr/bin/env python3
"""
Parse and stream /var/ossec/logs/alerts/alerts.log to frontend with structured data.
Also provides /api/chat endpoint for RAG-based threat intel chat + Wazuh alert search.
Run with sudo: sudo python3 server.py
"""
import os
import re
import sys
import time
import uuid
import json
import glob as glob_mod
import threading
from pathlib import Path
from flask import Flask, Response, send_from_directory, jsonify, request
from flask_cors import CORS

app = Flask(__name__, static_folder=None)
CORS(app)

ALERTS_LOG = os.environ.get("ALERTS_LOG", "/var/ossec/logs/alerts/alerts.log")
ALERTS_DIR = os.environ.get("ALERTS_DIR", "/var/ossec/logs/alerts")

# --- RAG Chat State (lazy-loaded) ---
_rag_retrieval = None
_chat_sessions = {}  # session_id -> list of {role, content}
MAX_HISTORY = 20
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")

# --- Wazuh Alert Store ---
_wazuh_alerts = []        # list of parsed alert dicts
_wazuh_alerts_lock = threading.Lock()
_wazuh_loaded = False
_wazuh_watch_pos = 0      # file position for tailing alerts.json

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant powered by the Wazuh AI Threat Engine.
You have access to two data sources:
1. A threat intelligence knowledge base containing MITRE ATT&CK techniques (823), YARA detection rules (378), and vendor security advisories (132).
2. Real Wazuh alert logs from this system — actual security events that have been detected.

When answering questions:
- If the user asks about what happened on the system, attacks detected, or specific alerts, use the Wazuh alert context.
- If the user asks about techniques, detection methods, or threat intelligence, use the knowledge base context.
- Cite specific technique IDs (e.g., T1055), rule IDs, alert timestamps, and severity levels.
- Summarize patterns you see in the alerts (e.g., repeated brute force, privilege escalation chains).
- Provide actionable security guidance based on what's observed.
- Keep answers concise but thorough."""


# ==================== Wazuh Alert Loading ====================


def _load_all_wazuh_alerts():
    """Load all historical Wazuh JSON alerts from /var/ossec/logs/alerts/."""
    global _wazuh_alerts, _wazuh_loaded, _wazuh_watch_pos

    if _wazuh_loaded:
        return

    alerts = []

    # Find all JSON alert files (historical rotated files)
    patterns = [
        os.path.join(ALERTS_DIR, "**", "ossec-alerts-*.json"),
    ]
    json_files = []
    for pattern in patterns:
        json_files.extend(glob_mod.glob(pattern, recursive=True))
    json_files.sort()

    # Load each file (one JSON object per line)
    for fpath in json_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
        except (PermissionError, OSError) as e:
            print(f"[alerts] Skipping {fpath}: {e}")

    # Load current alerts.json
    current_file = os.path.join(ALERTS_DIR, "alerts.json")
    if os.path.isfile(current_file):
        try:
            with open(current_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
                _wazuh_watch_pos = f.tell()
        except (PermissionError, OSError) as e:
            print(f"[alerts] Cannot read {current_file}: {e}")

    with _wazuh_alerts_lock:
        _wazuh_alerts = alerts
        _wazuh_loaded = True

    print(f"[alerts] Loaded {len(alerts)} historical Wazuh alerts")


def _check_new_alerts():
    """Check for new alerts appended to alerts.json since last read."""
    global _wazuh_watch_pos

    current_file = os.path.join(ALERTS_DIR, "alerts.json")
    if not os.path.isfile(current_file):
        return

    new_alerts = []
    try:
        with open(current_file, "r", encoding="utf-8", errors="replace") as f:
            f.seek(_wazuh_watch_pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    new_alerts.append(alert)
                except json.JSONDecodeError:
                    continue
            _wazuh_watch_pos = f.tell()
    except (PermissionError, OSError):
        return

    if new_alerts:
        with _wazuh_alerts_lock:
            _wazuh_alerts.extend(new_alerts)
        print(f"[alerts] Added {len(new_alerts)} new alerts (total: {len(_wazuh_alerts)})")


def _alert_to_text(alert):
    """Convert a Wazuh JSON alert to searchable text."""
    parts = []
    rule = alert.get("rule", {})
    parts.append(rule.get("description", ""))
    parts.append(f"level:{rule.get('level', 0)}")
    parts.append(f"rule:{rule.get('id', '')}")
    groups = rule.get("groups", [])
    if groups:
        parts.append(" ".join(groups))
    mitre = rule.get("mitre", {})
    if mitre:
        for tid in mitre.get("id", []):
            parts.append(tid)
        for tech in mitre.get("technique", []):
            parts.append(tech)
        for tac in mitre.get("tactic", []):
            parts.append(tac)
    parts.append(alert.get("full_log", ""))
    data = alert.get("data", {})
    if isinstance(data, dict):
        for k, v in data.items():
            parts.append(f"{k}:{v}")
    agent = alert.get("agent", {})
    parts.append(agent.get("name", ""))
    return " ".join(str(p) for p in parts).lower()


def _search_wazuh_alerts(query: str, top_k: int = 10) -> list:
    """Search Wazuh alerts by keyword matching and scoring."""
    if not _wazuh_loaded:
        _load_all_wazuh_alerts()

    # Check for new alerts on each search
    _check_new_alerts()

    with _wazuh_alerts_lock:
        alerts = list(_wazuh_alerts)

    if not alerts:
        return []

    query_lower = query.lower()
    query_terms = query_lower.split()

    scored = []
    for alert in alerts:
        text = _alert_to_text(alert)
        score = 0
        for term in query_terms:
            if term in text:
                score += 1
                # Bonus for exact matches in key fields
                rule_desc = alert.get("rule", {}).get("description", "").lower()
                if term in rule_desc:
                    score += 2
        if score > 0:
            scored.append((score, alert))

    # Sort by score descending, then by level descending
    scored.sort(key=lambda x: (x[0], x[1].get("rule", {}).get("level", 0)), reverse=True)

    return scored[:top_k]


def _format_alert_context(scored_alerts: list) -> tuple:
    """Format matched Wazuh alerts as context text and source list."""
    context_parts = []
    sources = []

    for i, (score, alert) in enumerate(scored_alerts, 1):
        rule = alert.get("rule", {})
        ts = alert.get("timestamp", "?")
        level = rule.get("level", 0)
        rid = rule.get("id", "?")
        desc = rule.get("description", "")
        full_log = alert.get("full_log", "")[:300]
        agent_name = alert.get("agent", {}).get("name", "?")
        groups = ", ".join(rule.get("groups", []))
        mitre = rule.get("mitre", {})
        mitre_ids = ", ".join(mitre.get("id", []))

        line = f"[A{i}] {ts} | Level {level} | Rule {rid} | {desc}"
        if mitre_ids:
            line += f" | MITRE: {mitre_ids}"
        line += f"\n     Agent: {agent_name} | Groups: {groups}"
        line += f"\n     Log: {full_log}"
        context_parts.append(line)

        sources.append({
            "id": f"Rule {rid}",
            "type": "wazuh_alert",
            "summary": f"[Level {level}] {desc} ({ts[:19]})",
            "score": round(score / 10, 3),
        })

    return "\n".join(context_parts), sources


# ==================== Threat Intel RAG ====================


def _get_retrieval():
    """Lazy-load the RAG retrieval system on first chat request."""
    global _rag_retrieval
    if _rag_retrieval is not None:
        return _rag_retrieval

    ai_engine_path = Path(__file__).resolve().parent.parent / "ai_threat_engine_starter"
    index_path = ai_engine_path / "data" / "threat_intel_index"

    if not index_path.exists() or not (index_path / "episodes.json").exists():
        print(f"[chat] Index not found at {index_path}. Run the indexer first.")
        return None

    starter_str = str(ai_engine_path)
    if starter_str not in sys.path:
        sys.path.insert(0, starter_str)

    from rag_core.indexing.hybrid_retrieval import HybridRetrieval

    print(f"[chat] Loading RAG index from {index_path}...")
    retrieval = HybridRetrieval(
        embedding_model="all-MiniLM-L6-v2",
        use_reranker=False,
        semantic_weight=0.6,
        keyword_weight=0.3,
        freshness_weight=0.1,
    )
    retrieval.load_index(str(index_path))
    print(f"[chat] Loaded {len(retrieval.episodes)} episodes")
    _rag_retrieval = retrieval
    return _rag_retrieval


def _search_knowledge_base(query: str, top_k: int = 5) -> list:
    """Search the threat intel knowledge base."""
    retrieval = _get_retrieval()
    if retrieval is None or not retrieval.episodes:
        return []

    results = retrieval.search(
        query=query,
        top_k=top_k,
        boost_freshness=False,
        use_reranking=False,
    )
    return results


def _call_ollama(messages: list) -> str:
    """Call Ollama's OpenAI-compatible chat completions API."""
    import requests

    url = f"{OLLAMA_URL}/v1/chat/completions"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 1024,
    }

    try:
        resp = requests.post(url, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except requests.exceptions.ConnectionError:
        return "Error: Cannot connect to Ollama. Make sure `ollama serve` is running."
    except requests.exceptions.Timeout:
        return "Error: Ollama request timed out. The model may still be loading."
    except Exception as e:
        return f"Error calling Ollama: {e}"


# ==================== Alert Streaming (SSE for dashboard) ====================


def parse_alert_block(lines):
    """Parse a multi-line alert block into structured data."""
    if not lines:
        return None

    alert = {
        "timestamp": "",
        "hostname": "",
        "program": "",
        "message": "",
        "level": 0,
        "rule_id": "",
        "rule_description": "",
        "tags": [],
        "alert_id": "",
        "source": "",
        "user": "",
        "raw_lines": []
    }

    for line in lines:
        alert["raw_lines"].append(line)

        if line.startswith("** Alert"):
            match = re.search(r'\*\* Alert ([0-9.]+):\s*-\s*(.+)', line)
            if match:
                alert["alert_id"] = match.group(1)
                alert["tags"] = [t.strip() for t in match.group(2).split(",")]

        elif re.match(r'\d{4}\s+\w+\s+\d+\s+\d+:\d+:\d+', line):
            parts = line.split("->")
            if len(parts) == 2:
                timestamp_host = parts[0].strip()
                alert["source"] = parts[1].strip()
                ts_parts = timestamp_host.split()
                if len(ts_parts) >= 4:
                    alert["timestamp"] = " ".join(ts_parts[:4])
                    alert["hostname"] = ts_parts[4] if len(ts_parts) > 4 else ""

        elif line.startswith("Rule:"):
            match = re.search(r'Rule:\s*(\d+)\s*\(level\s*(\d+)\)\s*->\s*[\'"](.+?)[\'"]', line)
            if match:
                alert["rule_id"] = match.group(1)
                alert["level"] = int(match.group(2))
                alert["rule_description"] = match.group(3)

        elif line.startswith("User:"):
            alert["user"] = line.split(":", 1)[1].strip()

        elif re.match(r'\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+\[?\d*\]?:', line):
            match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.+)', line)
            if match:
                if not alert["timestamp"]:
                    alert["timestamp"] = match.group(1)
                if not alert["hostname"]:
                    alert["hostname"] = match.group(2)
                alert["program"] = match.group(3)
                if match.group(4):
                    alert["program"] += f"[{match.group(4)}]"
                alert["message"] = match.group(5)

    if alert["rule_id"] or alert["message"]:
        return alert
    return None


def _parse_all_blocks(text):
    """Parse a chunk of alerts.log text into alert dicts."""
    alerts = []
    current_block = []
    for line in text.splitlines():
        if line.startswith("** Alert"):
            if current_block:
                alert = parse_alert_block(current_block)
                if alert:
                    alerts.append(alert)
            current_block = [line]
        elif line.strip():
            current_block.append(line)
        elif current_block:
            alert = parse_alert_block(current_block)
            if alert:
                alerts.append(alert)
            current_block = []
    # Last block
    if current_block:
        alert = parse_alert_block(current_block)
        if alert:
            alerts.append(alert)
    return alerts


BACKLOG_ALERTS = 50  # Number of recent alerts to show on page load


def stream_parsed_alerts():
    """Yield recent historical alerts then tail for new ones."""
    if not os.path.isfile(ALERTS_LOG):
        yield f"data: {json.dumps({'error': f'File not found: {ALERTS_LOG}'})}\n\n"
        return

    try:
        with open(ALERTS_LOG, "r", encoding="utf-8", errors="replace") as f:
            # --- Send recent backlog first ---
            content = f.read()
            backlog = _parse_all_blocks(content)
            for alert in backlog[-BACKLOG_ALERTS:]:
                yield f"data: {json.dumps(alert)}\n\n"

            # --- Now tail for new alerts ---
            current_block = []
            while True:
                line = f.readline()
                if line:
                    line = line.rstrip("\n")

                    if line.startswith("** Alert"):
                        if current_block:
                            alert = parse_alert_block(current_block)
                            if alert:
                                yield f"data: {json.dumps(alert)}\n\n"
                        current_block = [line]
                    elif line.strip():
                        current_block.append(line)
                    elif current_block:
                        alert = parse_alert_block(current_block)
                        if alert:
                            yield f"data: {json.dumps(alert)}\n\n"
                        current_block = []
                else:
                    time.sleep(0.2)
    except PermissionError:
        yield f"data: {json.dumps({'error': f'Permission denied: {ALERTS_LOG}. Run with sudo.'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


# ==================== Routes ====================


@app.route("/stream")
def sse_stream():
    return Response(
        stream_parsed_alerts(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/chat", methods=["POST"])
def chat():
    """RAG-powered chat endpoint with threat intel + Wazuh alert search.

    Request body: {"message": "...", "session_id": "..."}
    Response: {"reply": "...", "session_id": "...", "sources": [...]}
    """
    data = request.get_json(force=True)
    user_message = data.get("message", "").strip()
    session_id = data.get("session_id") or str(uuid.uuid4())

    if not user_message:
        return jsonify({"error": "message is required"}), 400

    # --- Search threat intel knowledge base ---
    ti_results = _search_knowledge_base(user_message, top_k=5)

    ti_context_parts = []
    sources = []
    for i, r in enumerate(ti_results, 1):
        summary = r.get("summary", "")[:500]
        etype = r.get("episode_type", "")
        eid = r.get("episode_id", "")
        score = r.get("score", 0)
        ti_context_parts.append(f"[{i}] ({etype}) {eid}: {summary}")
        sources.append({
            "id": eid,
            "type": etype,
            "summary": summary[:200],
            "score": round(score, 3),
        })

    ti_block = "\n".join(ti_context_parts) if ti_context_parts else "No relevant threat intel found."

    # --- Search Wazuh alerts ---
    alert_matches = _search_wazuh_alerts(user_message, top_k=10)
    alert_block, alert_sources = _format_alert_context(alert_matches)
    sources.extend(alert_sources)

    if not alert_block:
        alert_block = "No matching Wazuh alerts found."

    # --- Build LLM messages ---
    history = _chat_sessions.get(session_id, [])

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)

    augmented_message = (
        f"=== Threat Intelligence Context ===\n{ti_block}\n\n"
        f"=== Wazuh Alert Logs ({len(alert_matches)} matches from {len(_wazuh_alerts)} total alerts) ===\n{alert_block}\n\n"
        f"User question: {user_message}"
    )
    messages.append({"role": "user", "content": augmented_message})

    # Call LLM
    reply = _call_ollama(messages)

    # Update session history
    history.append({"role": "user", "content": user_message})
    history.append({"role": "assistant", "content": reply})
    if len(history) > MAX_HISTORY:
        history = history[-MAX_HISTORY:]
    _chat_sessions[session_id] = history

    return jsonify({
        "reply": reply,
        "session_id": session_id,
        "sources": sources,
    })


@app.route("/api/chat/sessions", methods=["DELETE"])
def clear_sessions():
    """Clear all chat sessions."""
    session_id = request.args.get("session_id")
    if session_id and session_id in _chat_sessions:
        del _chat_sessions[session_id]
    else:
        _chat_sessions.clear()
    return jsonify({"status": "ok"})


@app.route("/api/alerts/stats", methods=["GET"])
def alert_stats():
    """Return stats about loaded Wazuh alerts."""
    if not _wazuh_loaded:
        _load_all_wazuh_alerts()

    with _wazuh_alerts_lock:
        total = len(_wazuh_alerts)
        levels = {}
        groups = {}
        for a in _wazuh_alerts:
            rule = a.get("rule", {})
            lvl = rule.get("level", 0)
            levels[lvl] = levels.get(lvl, 0) + 1
            for g in rule.get("groups", []):
                groups[g] = groups.get(g, 0) + 1

    return jsonify({
        "total_alerts": total,
        "by_level": dict(sorted(levels.items(), key=lambda x: -x[1])),
        "top_groups": dict(sorted(groups.items(), key=lambda x: -x[1])[:15]),
    })


@app.route("/")
def index():
    return send_from_directory(os.path.join(os.path.dirname(__file__), "..", "frontend"), "index.html")


@app.route("/<path:path>")
def frontend_static(path):
    return send_from_directory(os.path.join(os.path.dirname(__file__), "..", "frontend"), path)


if __name__ == "__main__":
    print(f"Alerts log: {ALERTS_LOG}")
    print(f"Alerts dir: {ALERTS_DIR}")

    # Pre-load alerts at startup
    _load_all_wazuh_alerts()

    print("Open http://127.0.0.1:5000 in the browser.")
    print("Chat UI at http://127.0.0.1:5000/chat.html")
    print("Run with sudo if permission denied: sudo ./venv/bin/python server.py")
    app.run(host="0.0.0.0", port=5000, threaded=True)
