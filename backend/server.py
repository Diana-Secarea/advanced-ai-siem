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
import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the same directory as this file before anything else reads os.environ
load_dotenv(Path(__file__).resolve().parent / ".env")

from flask import Flask, Response, send_from_directory, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

_allowed_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000").split(",") if o.strip()]
CORS(app, origins=_allowed_origins)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri="memory://",
)

ALERTS_LOG = os.environ.get("ALERTS_LOG", "/var/ossec/logs/alerts/alerts.log")
ALERTS_DIR = os.environ.get("ALERTS_DIR", "/var/ossec/logs/alerts")

# ISO timestamp recorded once at startup — sent to the frontend so it can
# invalidate its localStorage cache whenever the server is restarted.
SERVER_START_TIME = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# --- RAG Chat State (lazy-loaded Qdrant store) ---
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

# --- User-defined Benign Rule Exceptions ---
BENIGN_RULES_FILE = os.path.join(os.path.dirname(__file__), "benign_rules.json")
_user_benign_rules = {}   # str(rule_id) -> {rule_id, rule_description, added_at}
_benign_rules_lock = threading.Lock()

# --- User-defined Suspicious Groups ---
SUSPICIOUS_GROUPS_FILE = os.path.join(os.path.dirname(__file__), "suspicious_groups.json")
SUGGESTED_SUSPICIOUS_FILE = (
    Path(__file__).resolve().parent.parent
    / "ai_threat_engine_starter"
    / "suggested_suspicious_groups.json"
)
_user_suspicious_groups = {}  # group_name -> {group_name, description, added_at}
_suspicious_groups_lock = threading.Lock()

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
- Keep answers concise but thorough.

IMPORTANT — Distinguish normal activity from threats:
- Alerts with rule level 1–5 and Anomaly Score labeled NORMAL are almost certainly routine system activity (logins, sudo, PAM sessions, cron jobs). Do NOT map these to attack techniques. State clearly that the activity appears benign.
- Only escalate to threat analysis when: rule level >= 7, OR Anomaly Score is HIGH, OR there is a clear pattern of malicious intent (e.g., repeated failures, off-hours, known-bad IPs).
- When threat intel context is absent (low-level alerts), say so explicitly and do not invent threat connections."""


# ==================== Wazuh Alert Loading ====================


def _load_all_wazuh_alerts():
    """Seek alerts.json to its current end — only NEW alerts (after server start) are collected.

    Historical rotated files are intentionally skipped so that the dashboard
    shows only the current monitoring session, not weeks of old data.
    """
    global _wazuh_alerts, _wazuh_loaded, _wazuh_watch_pos

    if _wazuh_loaded:
        return

    current_file = os.path.join(ALERTS_DIR, "alerts.json")
    if os.path.isfile(current_file):
        try:
            with open(current_file, "rb") as f:
                # Seek to end — anything already in the file is "old".
                # Only lines appended after this point will be collected.
                _wazuh_watch_pos = f.seek(0, 2)
        except (PermissionError, OSError) as e:
            print(f"[alerts] Cannot open {current_file}: {e}")

    with _wazuh_alerts_lock:
        _wazuh_alerts = []
        _wazuh_loaded = True

    print(f"[alerts] Session started — watching {current_file} from byte {_wazuh_watch_pos}")


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


def _load_benign_rules():
    """Load user-defined benign rule exceptions from disk on startup."""
    global _user_benign_rules
    if not os.path.exists(BENIGN_RULES_FILE):
        return
    try:
        with open(BENIGN_RULES_FILE, "r") as f:
            data = json.load(f)
        with _benign_rules_lock:
            _user_benign_rules = data
        print(f"[benign] Loaded {len(_user_benign_rules)} user-defined benign rules")
    except Exception as e:
        print(f"[benign] Failed to load benign rules: {e}")


def _save_benign_rules():
    """Persist the current user benign rules to disk. Must be called under _benign_rules_lock."""
    try:
        with open(BENIGN_RULES_FILE, "w") as f:
            json.dump(_user_benign_rules, f, indent=2)
    except Exception as e:
        print(f"[benign] Failed to save benign rules: {e}")


_load_benign_rules()


def _load_suspicious_groups():
    """Load user-defined suspicious groups from disk on startup."""
    global _user_suspicious_groups
    if not os.path.exists(SUSPICIOUS_GROUPS_FILE):
        return
    try:
        with open(SUSPICIOUS_GROUPS_FILE, "r") as f:
            data = json.load(f)
        with _suspicious_groups_lock:
            _user_suspicious_groups = data
        print(f"[suspicious] Loaded {len(_user_suspicious_groups)} user-defined suspicious groups")
    except Exception as e:
        print(f"[suspicious] Failed to load suspicious groups: {e}")


def _save_suspicious_groups():
    """Persist suspicious groups to disk. Must be called under _suspicious_groups_lock."""
    try:
        with open(SUSPICIOUS_GROUPS_FILE, "w") as f:
            json.dump(_user_suspicious_groups, f, indent=2)
    except Exception as e:
        print(f"[suspicious] Failed to save suspicious groups: {e}")


_load_suspicious_groups()


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


def _format_alert_context(scored_alerts: list, anomaly_scores: dict = None,
                           ae_scores: dict = None) -> tuple:
    """Format matched Wazuh alerts as context text and source list.

    anomaly_scores: optional dict index -> {anomaly_label, combined_score, score}
    ae_scores: ignored (kept for signature compatibility, no longer used)
    """
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

        idx = i - 1
        if anomaly_scores and idx in anomaly_scores:
            info  = anomaly_scores[idx]
            label = info.get("anomaly_label", "UNKNOWN")
            comb  = info.get("combined_score", info.get("score", "?"))
            line += f" | {label} (combined {comb}/100)"

        line += f"\n     Agent: {agent_name} | Groups: {groups}"
        line += f"\n     Log: {full_log}"
        context_parts.append(line)

        score_label = ""
        if anomaly_scores and idx in anomaly_scores:
            info  = anomaly_scores[idx]
            label = info.get("anomaly_label", "UNKNOWN")
            comb  = info.get("combined_score", info.get("score", "?"))
            score_label = f" | {label} (combined {comb}/100)"

        sources.append({
            "id": f"Rule {rid}",
            "type": "wazuh_alert",
            "summary": f"[Level {level}] {desc} ({ts[:19]}){score_label}",
            "score": round(score / 10, 3),
        })

    return "\n".join(context_parts), sources


# ==================== Threat Intel RAG ====================


def _get_retrieval():
    """Lazy-load the Qdrant-backed hybrid retrieval store on first chat request."""
    global _rag_retrieval
    if _rag_retrieval is not None:
        return _rag_retrieval

    ai_engine_path = Path(__file__).resolve().parent.parent / "ai_threat_engine_starter"
    starter_str = str(ai_engine_path)
    if starter_str not in sys.path:
        sys.path.insert(0, starter_str)

    try:
        from rag_core.database.qdrant_store import QdrantStore
        store = QdrantStore()
        if not store.ping():
            print("[chat] Qdrant is not reachable. Run: docker compose up -d")
            return None
        info = store.collection_info()
        print(f"[chat] Connected to Qdrant — {info['points_count']} points in '{info['name']}'")
        _rag_retrieval = store
    except Exception as e:
        print(f"[chat] Failed to connect to Qdrant: {e}")
        return None

    return _rag_retrieval


_ensemble = None


def _get_ensemble():
    """Lazy-load the IF + Autoencoder ensemble on first use."""
    global _ensemble
    if _ensemble is not None:
        return _ensemble

    ai_engine_path = Path(__file__).resolve().parent.parent / "ai_threat_engine_starter"
    engine_str = str(ai_engine_path)
    if engine_str not in sys.path:
        sys.path.insert(0, engine_str)

    try:
        from autoencoders_approach.ensemble_detector import load_ensemble
        _ensemble = load_ensemble()
        ae_status = "IF+AE" if _ensemble.ae_det is not None else "IF-only"
        print(f"[ensemble] Loaded anomaly ensemble ({ae_status})")
    except Exception as e:
        print(f"[ensemble] Failed to load ensemble: {e}")
        return None

    return _ensemble


# Keep legacy accessor so any code that calls _get_anomaly_detector() still works.
def _get_anomaly_detector():
    ens = _get_ensemble()
    return ens.if_det if ens else None


def _search_knowledge_base(query: str, top_k: int = 5) -> list:
    """Search the threat intel knowledge base via Qdrant hybrid retrieval (dense + BM25 → RRF)."""
    store = _get_retrieval()
    if store is None:
        return []

    try:
        return store.search(query=query, top_k=top_k)
    except Exception as e:
        print(f"[chat] Qdrant search error: {e}")
        return []


def _call_ollama(messages: list) -> str:
    """Call Ollama's OpenAI-compatible chat completions API (blocking)."""
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


def _stream_ollama(messages: list):
    """Yield text chunks from Ollama using server-sent events (NDJSON stream)."""
    import requests

    url = f"{OLLAMA_URL}/v1/chat/completions"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 1024,
        "stream": True,
    }

    try:
        with requests.post(url, json=payload, stream=True, timeout=120) as resp:
            resp.raise_for_status()
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
                if line.startswith("data: "):
                    line = line[6:]
                if line == "[DONE]":
                    return
                try:
                    chunk = json.loads(line)
                    delta = chunk["choices"][0].get("delta", {})
                    token = delta.get("content", "")
                    if token:
                        yield token
                except (json.JSONDecodeError, KeyError):
                    continue
    except requests.exceptions.ConnectionError:
        yield "\n\nError: Cannot connect to Ollama. Make sure `ollama serve` is running."
    except requests.exceptions.Timeout:
        yield "\n\nError: Ollama request timed out."
    except Exception as e:
        yield f"\n\nError calling Ollama: {e}"


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
                if line == "":
                    # True EOF — no new data yet
                    time.sleep(0.2)
                else:
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
                        # Blank line = end of alert block
                        alert = parse_alert_block(current_block)
                        if alert:
                            yield f"data: {json.dumps(alert)}\n\n"
                        current_block = []
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


@app.route("/api/alerts/scored")
def api_alerts_scored():
    """Return recent Wazuh alerts scored by the Isolation Forest anomaly detector.

    Query params:
        limit (int): max alerts to return (default 100, max 500)

    Returns alerts sorted by anomaly score descending (most anomalous first).
    """
    limit = min(int(request.args.get("limit", 100)), 500)

    if not _wazuh_loaded:
        _load_all_wazuh_alerts()
    _check_new_alerts()

    with _wazuh_alerts_lock:
        alerts = list(_wazuh_alerts)

    # Take the most recent N alerts
    recent = alerts[-limit:] if len(alerts) > limit else alerts

    ensemble = _get_ensemble()

    result = []
    for alert in recent:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        mitre = rule.get("mitre", {})
        data = alert.get("data", {})

        anomaly_score  = None
        is_anomaly     = None
        anomaly_label  = "UNKNOWN"
        ae_score       = None
        combined_score = None

        if ensemble:
            try:
                ens_r          = ensemble.score(alert)
                anomaly_score  = ens_r["if_score"]
                ae_score       = ens_r["ae_score"]
                combined_score = ens_r["combined_score"]
                is_anomaly     = ens_r["is_anomaly"]
                anomaly_label  = ens_r["anomaly_label"]
            except Exception:
                pass

        # User-defined benign exceptions override ensemble verdict.
        rule_id_str = str(rule.get("id", ""))
        with _benign_rules_lock:
            is_user_benign = rule_id_str in _user_benign_rules
        if is_user_benign:
            anomaly_score  = 0
            ae_score       = 0
            combined_score = 0
            is_anomaly     = False
            anomaly_label  = "BENIGN"

        result.append({
            "timestamp":       alert.get("timestamp", ""),
            "level":           rule.get("level", 0),
            "rule_id":         rule.get("id", ""),
            "rule_description": rule.get("description", ""),
            "agent_name":      agent.get("name", ""),
            "agent_ip":        agent.get("ip", ""),
            "full_log":        alert.get("full_log", "")[:500],
            "groups":          rule.get("groups", []),
            "mitre_ids":       mitre.get("id", []),
            "data":            {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {},
            "anomaly_score":   anomaly_score,
            "autoencoder_score": ae_score,
            "combined_score":  combined_score,
            "is_anomaly":      is_anomaly,
            "anomaly_label":   anomaly_label,
        })

    # Sort: highest anomaly score first
    result.sort(key=lambda x: x.get("anomaly_score") or 0, reverse=True)

    return jsonify({"alerts": result, "total": len(result), "server_start": SERVER_START_TIME})


@app.route("/api/chat", methods=["POST"])
@limiter.limit("20 per minute")
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

    # --- Search Wazuh alerts first (needed to determine level gate) ---
    alert_matches = _search_wazuh_alerts(user_message, top_k=10)

    # --- Score each matched alert with the ensemble ---
    anomaly_scores = {}
    ae_scores = {}
    ensemble = _get_ensemble()
    if ensemble:
        for idx, (_, alert) in enumerate(alert_matches):
            try:
                ens_r = ensemble.score(alert)
                anomaly_scores[idx] = {
                    "anomaly_label": ens_r["anomaly_label"],
                    "combined_score": ens_r["combined_score"],
                    "score":         ens_r["if_score"],
                }
            except Exception:
                pass

    # --- Gate threat intel retrieval by alert level ---
    # Only fetch MITRE/YARA context if at least one matched alert is level >= 5.
    # For low-level routine events (1-4) the LLM should not be primed with attack techniques.
    max_alert_level = max(
        (a.get("rule", {}).get("level", 0) for _, a in alert_matches),
        default=0,
    )
    fetch_threat_intel = (not alert_matches) or (max_alert_level >= 5)

    ti_context_parts = []
    sources = []

    if fetch_threat_intel:
        ti_results = _search_knowledge_base(user_message, top_k=5)
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

    if fetch_threat_intel:
        ti_block = "\n".join(ti_context_parts) if ti_context_parts else "No relevant threat intel found."
    else:
        ti_block = (
            f"Threat intel skipped — all matched alerts are level {max_alert_level} (< 5). "
            "These are likely routine events. Do not map to attack techniques without further evidence."
        )

    alert_block, alert_sources = _format_alert_context(alert_matches, anomaly_scores, ae_scores)
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


@app.route("/api/chat/stream", methods=["POST"])
@limiter.limit("20 per minute")
def chat_stream():
    """SSE streaming version of /api/chat.

    Sends token chunks as 'data: <token>' SSE lines, then a final
    'event: done' with JSON containing session_id and sources.
    """
    data = request.get_json(force=True)
    user_message = data.get("message", "").strip()
    session_id = data.get("session_id") or str(uuid.uuid4())

    if not user_message:
        return jsonify({"error": "message is required"}), 400

    # --- Same RAG pipeline as /api/chat ---
    alert_matches = _search_wazuh_alerts(user_message, top_k=10)

    anomaly_scores = {}
    ae_scores = {}
    ensemble = _get_ensemble()
    if ensemble:
        for idx, (_, alert) in enumerate(alert_matches):
            try:
                ens_r = ensemble.score(alert)
                anomaly_scores[idx] = {
                    "anomaly_label": ens_r["anomaly_label"],
                    "combined_score": ens_r["combined_score"],
                    "score":         ens_r["if_score"],
                }
            except Exception:
                pass

    max_alert_level = max(
        (a.get("rule", {}).get("level", 0) for _, a in alert_matches),
        default=0,
    )
    fetch_threat_intel = (not alert_matches) or (max_alert_level >= 5)

    ti_context_parts = []
    sources = []

    if fetch_threat_intel:
        ti_results = _search_knowledge_base(user_message, top_k=5)
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

    if fetch_threat_intel:
        ti_block = "\n".join(ti_context_parts) if ti_context_parts else "No relevant threat intel found."
    else:
        ti_block = (
            f"Threat intel skipped — all matched alerts are level {max_alert_level} (< 5). "
            "These are likely routine events. Do not map to attack techniques without further evidence."
        )

    alert_block, alert_sources = _format_alert_context(alert_matches, anomaly_scores, ae_scores)
    sources.extend(alert_sources)
    if not alert_block:
        alert_block = "No matching Wazuh alerts found."

    history = _chat_sessions.get(session_id, [])
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    augmented_message = (
        f"=== Threat Intelligence Context ===\n{ti_block}\n\n"
        f"=== Wazuh Alert Logs ({len(alert_matches)} matches from {len(_wazuh_alerts)} total alerts) ===\n{alert_block}\n\n"
        f"User question: {user_message}"
    )
    messages.append({"role": "user", "content": augmented_message})

    def generate():
        full_reply = []
        for token in _stream_ollama(messages):
            full_reply.append(token)
            # Escape newlines so each SSE data line is valid
            safe = token.replace("\n", "\\n")
            yield f"data: {safe}\n\n"

        # Save to session history after streaming completes
        reply_text = "".join(full_reply)
        hist = _chat_sessions.get(session_id, [])
        hist.append({"role": "user", "content": user_message})
        hist.append({"role": "assistant", "content": reply_text})
        if len(hist) > MAX_HISTORY:
            hist = hist[-MAX_HISTORY:]
        _chat_sessions[session_id] = hist

        # Final event carries metadata
        done_payload = json.dumps({"session_id": session_id, "sources": sources})
        yield f"event: done\ndata: {done_payload}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/chat/sessions", methods=["DELETE"])
def clear_sessions():
    """Clear all chat sessions."""
    session_id = request.args.get("session_id")
    if session_id and session_id in _chat_sessions:
        del _chat_sessions[session_id]
    else:
        _chat_sessions.clear()
    return jsonify({"status": "ok"})


SUGGESTED_BENIGN_FILE = (
    Path(__file__).resolve().parent.parent
    / "ai_threat_engine_starter"
    / "suggested_benign_rule_ids.json"
)


@app.route("/api/suggested-benign-rules", methods=["GET"])
def get_suggested_benign_rules():
    """Return the curated list of commonly-benign rule IDs for the user to review."""
    try:
        with open(SUGGESTED_BENIGN_FILE, "r") as f:
            data = json.load(f)
        rules = [{"rule_id": k, "rule_description": v} for k, v in data.items()]
        return jsonify({"rules": rules})
    except Exception as e:
        return jsonify({"rules": [], "error": str(e)})


@app.route("/api/benign-rules", methods=["GET"])
def get_benign_rules():
    """Return all user-defined benign rule exceptions."""
    with _benign_rules_lock:
        rules = list(_user_benign_rules.values())
    rules.sort(key=lambda r: r.get("added_at", ""), reverse=True)
    return jsonify({"rules": rules})


@app.route("/api/benign-rules", methods=["POST"])
def add_benign_rule():
    """Add a rule ID to the user-defined benign exceptions list."""
    data = request.get_json(force=True)
    rule_id = str(data.get("rule_id", "")).strip()
    rule_description = str(data.get("rule_description", "")).strip()
    if not rule_id:
        return jsonify({"error": "rule_id is required"}), 400
    entry = {
        "rule_id": rule_id,
        "rule_description": rule_description,
        "added_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with _benign_rules_lock:
        _user_benign_rules[rule_id] = entry
        _save_benign_rules()
    print(f"[benign] Added rule {rule_id}: {rule_description}")
    return jsonify({"status": "ok", "rule": entry})


@app.route("/api/benign-rules/<rule_id>", methods=["DELETE"])
def remove_benign_rule(rule_id):
    """Remove a rule ID from the user-defined benign exceptions list."""
    rule_id = str(rule_id).strip()
    with _benign_rules_lock:
        if rule_id not in _user_benign_rules:
            return jsonify({"error": "Rule not found"}), 404
        del _user_benign_rules[rule_id]
        _save_benign_rules()
    print(f"[benign] Removed rule {rule_id}")
    return jsonify({"status": "ok"})


@app.route("/api/suggested-suspicious-groups", methods=["GET"])
def get_suggested_suspicious_groups():
    """Return the curated list of commonly-suspicious groups for the user to review."""
    try:
        with open(SUGGESTED_SUSPICIOUS_FILE, "r") as f:
            data = json.load(f)
        groups = [{"group_name": k, "description": v} for k, v in data.items()]
        return jsonify({"groups": groups})
    except Exception as e:
        return jsonify({"groups": [], "error": str(e)})


@app.route("/api/suspicious-groups", methods=["GET"])
def get_suspicious_groups():
    """Return all user-defined active suspicious groups."""
    with _suspicious_groups_lock:
        groups = list(_user_suspicious_groups.values())
    groups.sort(key=lambda g: g.get("added_at", ""), reverse=True)
    return jsonify({"groups": groups})


@app.route("/api/suspicious-groups", methods=["POST"])
def add_suspicious_group():
    """Add a group name to the user-defined suspicious groups list."""
    data = request.get_json(force=True)
    group_name = str(data.get("group_name", "")).strip()
    description = str(data.get("description", "")).strip()
    if not group_name:
        return jsonify({"error": "group_name is required"}), 400
    entry = {
        "group_name": group_name,
        "description": description,
        "added_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with _suspicious_groups_lock:
        _user_suspicious_groups[group_name] = entry
        _save_suspicious_groups()
    print(f"[suspicious] Added group '{group_name}'")
    return jsonify({"status": "ok", "group": entry})


@app.route("/api/suspicious-groups/<path:group_name>", methods=["DELETE"])
def remove_suspicious_group(group_name):
    """Remove a group name from the user-defined suspicious groups list."""
    group_name = group_name.strip()
    with _suspicious_groups_lock:
        if group_name not in _user_suspicious_groups:
            return jsonify({"error": "Group not found"}), 404
        del _user_suspicious_groups[group_name]
        _save_suspicious_groups()
    print(f"[suspicious] Removed group '{group_name}'")
    return jsonify({"status": "ok"})


def _chunk_text(text: str, chunk_size: int = 1500, overlap: int = 200) -> list:
    """Split text into overlapping chunks for indexing."""
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start:start + chunk_size])
        next_start = start + chunk_size - overlap
        if next_start <= start:
            break
        start = next_start
    return [c for c in chunks if c.strip()]


@app.route("/api/knowledge/upload", methods=["POST"])
@limiter.limit("10 per minute")
def upload_document():
    """Upload a document into the RAG knowledge base (Qdrant + Postgres).

    Form fields:
        file    — the document (.txt, .md, .json)
        title   — human-readable title (optional, defaults to filename)
        tags    — comma-separated tags (optional)
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()

    if ext == ".pdf":
        return jsonify({"error": "PDF not supported — please convert to .txt or .md first"}), 400
    if ext not in (".txt", ".md", ".json", ""):
        return jsonify({"error": f"Unsupported file type '{ext}'. Use .txt, .md, or .json"}), 400

    title = request.form.get("title", "").strip() or filename
    tags_raw = request.form.get("tags", "").strip()
    user_tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

    try:
        raw = file.read()
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 500

    if len(raw) > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (max 5 MB)"}), 400

    if ext == ".json":
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            text = json.dumps(parsed, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as e:
            return jsonify({"error": f"Invalid JSON: {e}"}), 400
    else:
        text = raw.decode("utf-8", errors="replace")

    text = text.strip()
    if not text:
        return jsonify({"error": "Document is empty"}), 400

    chunks = _chunk_text(text)
    doc_id = str(uuid.uuid4())[:8]
    uploaded_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    all_tags = list(set(user_tags + ["user_upload"]))

    episodes = []
    for i, chunk in enumerate(chunks):
        ep_id = (
            f"user_upload/{doc_id}"
            if len(chunks) == 1
            else f"user_upload/{doc_id}/chunk_{i}"
        )
        meta = {"title": title, "filename": filename, "uploaded_at": uploaded_at, "doc_id": doc_id}
        if len(chunks) > 1:
            meta.update({"chunk": i, "total_chunks": len(chunks)})
        episodes.append({
            "episode_id":   ep_id,
            "episode_type": "user_document",
            "source":       "user_upload",
            "summary":      chunk,
            "tags":         all_tags,
            "entities":     {},
            "metadata":     meta,
            "time_range":   {},
            "raw_refs":     [],
        })

    store = _get_retrieval()
    if store is None:
        return jsonify({"error": "Qdrant is not available — is Docker running?"}), 503

    try:
        n = store.index_episodes(episodes)
    except Exception as e:
        return jsonify({"error": f"Qdrant indexing failed: {e}"}), 500

    # Write to Postgres (non-fatal if unavailable)
    try:
        ai_engine_path = Path(__file__).resolve().parent.parent / "ai_threat_engine_starter"
        starter_str = str(ai_engine_path)
        if starter_str not in sys.path:
            sys.path.insert(0, starter_str)
        from rag_core.database.postgres_client import upsert_threat_intel
        pg_records = [
            {
                "id":          ep["episode_id"],
                "source_type": "user_upload",
                "name":        title,
                "description": ep["summary"][:1000],
                "tags":        all_tags,
                "raw_data":    ep,
            }
            for ep in episodes
        ]
        upsert_threat_intel(pg_records)
    except Exception as e:
        print(f"[upload] Postgres write failed (non-fatal): {e}")

    print(f"[upload] Indexed '{title}' ({filename}) → {n} Qdrant points, doc_id={doc_id}")
    return jsonify({
        "status":       "ok",
        "doc_id":       doc_id,
        "title":        title,
        "chunks":       len(chunks),
        "points_added": n,
    })


@app.route("/api/knowledge/documents", methods=["GET"])
def list_documents():
    """Return all user-uploaded documents from the knowledge base."""
    store = _get_retrieval()
    if store is None:
        return jsonify({"error": "Qdrant is not available — is Docker running?"}), 503
    try:
        docs = store.list_user_documents()
        return jsonify({"documents": docs, "total": len(docs)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/knowledge/documents/<doc_id>", methods=["DELETE"])
def delete_document(doc_id):
    """Delete a user-uploaded document and all its vectors from the knowledge base."""
    doc_id = doc_id.strip()
    if not doc_id:
        return jsonify({"error": "doc_id is required"}), 400

    store = _get_retrieval()
    if store is None:
        return jsonify({"error": "Qdrant is not available — is Docker running?"}), 503

    try:
        store.delete_document(doc_id)
    except Exception as e:
        return jsonify({"error": f"Qdrant deletion failed: {e}"}), 500

    # Also remove from Postgres (non-fatal)
    try:
        ai_engine_path = Path(__file__).resolve().parent.parent / "ai_threat_engine_starter"
        starter_str = str(ai_engine_path)
        if starter_str not in sys.path:
            sys.path.insert(0, starter_str)
        from rag_core.database.postgres_client import get_conn
        conn = get_conn()
        with conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM threat_intel WHERE source_type = 'user_upload' "
                "AND raw_data->>'episode_id' LIKE %s",
                (f"user_upload/{doc_id}%",),
            )
    except Exception as e:
        print(f"[upload] Postgres delete failed (non-fatal): {e}")

    print(f"[upload] Deleted document doc_id={doc_id}")
    return jsonify({"status": "ok", "doc_id": doc_id})


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


@app.route("/api/vectordb/stats")
def vectordb_stats():
    """Return Qdrant statistics for the Vector DB Dashboard.

    Queries Qdrant's REST API directly (no embedding model needed) to return
    collection info, per-source document counts, and version metadata.
    """
    import requests as _req

    qdrant_base = f"http://{os.environ.get('QDRANT_HOST', 'localhost')}:{os.environ.get('QDRANT_PORT', '6333')}"

    SOURCE_LABELS = {
        "sigma":                  {"label": "Sigma Rules",          "color": "amber"},
        "cisa_kev":               {"label": "CISA KEV",             "color": "red"},
        "mitre_attack":           {"label": "MITRE ATT&CK",         "color": "cyan"},
        "cis_controls":           {"label": "CIS Controls",         "color": "green"},
        "user_upload":            {"label": "User Uploads",         "color": "purple"},
        "mitre_d3fend":           {"label": "MITRE D3FEND",         "color": "cyan"},
        "mitre_groups_software":  {"label": "MITRE Groups",         "color": "purple"},
        "otx_alienvault":         {"label": "OTX AlienVault",       "color": "amber"},
    }
    COLLECTION_NAMES = ["wazuh_threat_intel", "wazuh_alert_episodes"]

    result = {
        "status": "error",
        "qdrant_version": None,
        "qdrant_startup": None,
        "collections": [],
        "source_breakdown": [],
        "total_points": 0,
        "total_embeddings": 0,
    }

    try:
        # --- Version / uptime ---
        tel = _req.get(f"{qdrant_base}/telemetry", timeout=3).json()
        app_info = tel.get("result", {}).get("app", {})
        result["qdrant_version"] = app_info.get("version")
        result["qdrant_startup"] = app_info.get("startup")

        # --- Per-collection info ---
        for cname in COLLECTION_NAMES:
            try:
                cinfo = _req.get(f"{qdrant_base}/collections/{cname}", timeout=3).json()
                cr = cinfo.get("result", {})
                vec_params = cr.get("config", {}).get("params", {}).get("vectors", {})
                if isinstance(vec_params, dict) and "dense" in vec_params:
                    vec_dim = vec_params["dense"].get("size", 0)
                elif isinstance(vec_params, dict) and "size" in vec_params:
                    vec_dim = vec_params.get("size", 0)
                else:
                    vec_dim = 0
                result["collections"].append({
                    "name":                  cname,
                    "status":                cr.get("status", "unknown"),
                    "optimizer_status":      cr.get("optimizer_status", "unknown"),
                    "points_count":          cr.get("points_count", 0) or 0,
                    "indexed_vectors_count": cr.get("indexed_vectors_count", 0) or 0,
                    "segments_count":        cr.get("segments_count", 0) or 0,
                    "vector_dim":            vec_dim,
                    "on_disk_payload":       cr.get("config", {}).get("params", {}).get("on_disk_payload", False),
                })
                result["total_points"]     += cr.get("points_count", 0) or 0
                result["total_embeddings"] += cr.get("indexed_vectors_count", 0) or 0
            except Exception:
                result["collections"].append({"name": cname, "status": "unreachable", "points_count": 0,
                                              "indexed_vectors_count": 0, "segments_count": 0, "vector_dim": 0})

        # --- Per-source breakdown (threat intel collection only) ---
        breakdown = []
        for src, meta in SOURCE_LABELS.items():
            try:
                cnt_resp = _req.post(
                    f"{qdrant_base}/collections/wazuh_threat_intel/points/count",
                    json={"filter": {"must": [{"key": "source_type", "match": {"value": src}}]}, "exact": True},
                    timeout=3,
                ).json()
                count = cnt_resp.get("result", {}).get("count", 0) or 0
                if count > 0:
                    breakdown.append({"source": src, "label": meta["label"], "color": meta["color"], "count": count})
            except Exception:
                pass
        breakdown.sort(key=lambda x: x["count"], reverse=True)
        result["source_breakdown"] = breakdown
        result["status"] = "ok"

    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)


# ===========================================================================
# CVE Ingestion Agent  (scheduled_agent/) — run + visibility endpoints
# ===========================================================================
AI_ENGINE_DIR = Path(__file__).resolve().parent.parent / "ai_threat_engine_starter"
AGENT_VENV_PY = AI_ENGINE_DIR / "venv" / "bin" / "python3"

# In-memory state for the currently/last running job (one at a time)
_cve_run = {
    "running": False, "source": None, "log": [],
    "started_at": None, "finished_at": None, "returncode": None,
}
_cve_run_lock = threading.Lock()


def _agent_db_conn():
    """psycopg2 connection to the agent's Postgres, via rag_core."""
    starter = str(AI_ENGINE_DIR)
    if starter not in sys.path:
        sys.path.insert(0, starter)
    from rag_core.database.postgres_client import get_conn
    return get_conn()


def _run_cve_agent(source: str):
    """Background thread: run the agent as a subprocess, stream its output."""
    import subprocess
    cmd = [str(AGENT_VENV_PY), "-m", "scheduled_agent.agent", "--source", source]
    rc = -1
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(AI_ENGINE_DIR),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env={**os.environ},
        )
        for line in proc.stdout:
            with _cve_run_lock:
                _cve_run["log"].append(line.rstrip("\n"))
                if len(_cve_run["log"]) > 2000:
                    _cve_run["log"] = _cve_run["log"][-2000:]
        proc.wait()
        rc = proc.returncode
    except Exception as e:
        with _cve_run_lock:
            _cve_run["log"].append(f"[server] run failed: {e}")
    finally:
        with _cve_run_lock:
            _cve_run["running"] = False
            _cve_run["returncode"] = rc
            _cve_run["finished_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


@app.route("/api/cve-agent/run", methods=["POST"])
def cve_agent_run():
    """Trigger an agent run in the background. One run at a time."""
    source = (request.get_json(silent=True) or {}).get("source", "all")
    if source not in ("all", "nvd", "cisa_kev"):
        source = "all"
    with _cve_run_lock:
        if _cve_run["running"]:
            return jsonify({"error": "A run is already in progress", "running": True}), 409
        _cve_run.update({
            "running": True, "source": source, "log": [],
            "started_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at": None, "returncode": None,
        })
    threading.Thread(target=_run_cve_agent, args=(source,), daemon=True).start()
    return jsonify({"status": "started", "source": source})


@app.route("/api/cve-agent/run-status", methods=["GET"])
def cve_agent_run_status():
    """Live status + log of the current/last run (frontend polls this)."""
    with _cve_run_lock:
        return jsonify({
            "running":     _cve_run["running"],
            "source":      _cve_run["source"],
            "log":         list(_cve_run["log"]),
            "started_at":  _cve_run["started_at"],
            "finished_at": _cve_run["finished_at"],
            "returncode":  _cve_run["returncode"],
        })


@app.route("/api/cve-agent/status", methods=["GET"])
def cve_agent_status():
    """Overview from the Postgres ledger: last run per source, totals, recent indexed."""
    try:
        conn = _agent_db_conn()
    except Exception as e:
        return jsonify({"error": f"Postgres unavailable: {e}"}), 503
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT ON (source_type)
                       source_type, started_at, finished_at, status,
                       cves_evaluated, cves_indexed, cves_queued,
                       cves_dropped, cves_duplicate
                FROM ingestion_log
                WHERE source_type IN ('cve_agent_nvd', 'cve_agent_cisa_kev')
                ORDER BY source_type, started_at DESC
            """)
            runs = [{
                "source": r[0].replace("cve_agent_", ""),
                "started_at": r[1].isoformat() if r[1] else None,
                "finished_at": r[2].isoformat() if r[2] else None,
                "status": r[3],
                "evaluated": r[4], "indexed": r[5], "queued": r[6],
                "dropped": r[7], "duplicate": r[8],
            } for r in cur.fetchall()]

            cur.execute("SELECT decision, COUNT(*) FROM cve_decisions GROUP BY decision")
            totals = {row[0]: row[1] for row in cur.fetchall()}

            cur.execute("""
                SELECT cve_id, source_type, final_score, boost, decided_at
                FROM cve_decisions WHERE decision = 'indexed'
                ORDER BY decided_at DESC LIMIT 15
            """)
            recent = [{
                "cve_id": r[0], "source": r[1], "score": r[2],
                "boost": r[3], "decided_at": r[4].isoformat() if r[4] else None,
            } for r in cur.fetchall()]

            last_run = max(
                (r["started_at"] for r in runs if r["started_at"]), default=None
            )
    finally:
        conn.close()

    return jsonify({
        "runs": runs,
        "totals": {
            "indexed":   totals.get("indexed", 0),
            "queued":    totals.get("queued", 0),
            "dropped":   totals.get("dropped", 0),
            "duplicate": totals.get("duplicate", 0),
        },
        "recent_indexed": recent,
        "last_run": last_run,
    })


@app.route("/api/cve-agent/queue", methods=["GET"])
def cve_agent_queue():
    """Pending human-review queue (mid-score CVEs held out of RAG)."""
    try:
        conn = _agent_db_conn()
    except Exception as e:
        return jsonify({"error": f"Postgres unavailable: {e}"}), 503
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id, source_type, final_score, reasoning,
                       boost_reason, decided_at
                FROM pending_review LIMIT 100
            """)
            queue = [{
                "cve_id": r[0], "source": r[1], "score": r[2],
                "reasoning": r[3], "boost_reason": r[4],
                "decided_at": r[5].isoformat() if r[5] else None,
            } for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify({"queue": queue, "total": len(queue)})


@app.route("/api/cve-agent/cve/<path:cve_id>", methods=["GET"])
def cve_agent_cve_detail(cve_id):
    """Full ledger record + parsed details for one CVE (for the detail modal)."""
    cve_id = cve_id.strip().upper()
    try:
        conn = _agent_db_conn()
    except Exception as e:
        return jsonify({"error": f"Postgres unavailable: {e}"}), 503
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id, source_type, base_score, boost, final_score,
                       decision, reasoning, boost_reason, raw_cve, qdrant_id, decided_at
                FROM cve_decisions WHERE cve_id = %s
                ORDER BY decided_at DESC LIMIT 1
            """, (cve_id,))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": f"{cve_id} not found in the ledger"}), 404

    (cid, source, base, boost, final, decision,
     reasoning, boost_reason, raw, qid, decided) = row

    starter = str(AI_ENGINE_DIR)
    if starter not in sys.path:
        sys.path.insert(0, starter)
    try:
        from scheduled_agent import normalize
        parsed = (normalize.parse_nvd_item({"cve": raw}) if source == "nvd"
                  else normalize.parse_kev_item(raw))
    except Exception:
        parsed = {"description": "", "products": [], "vendor": "", "cvss": None, "published": ""}

    return jsonify({
        "cve_id": cid, "source": source, "decision": decision,
        "base_score": base, "boost": boost, "final_score": final,
        "reasoning": reasoning, "boost_reason": boost_reason,
        "decided_at": decided.isoformat() if decided else None,
        "qdrant_id": qid,
        "description": parsed.get("description", ""),
        "products": parsed.get("products", []),
        "vendor": parsed.get("vendor", ""),
        "cvss": parsed.get("cvss"),
        "published": parsed.get("published", ""),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
    })


@app.route("/api/cve-agent/approve", methods=["POST"])
def cve_agent_approve():
    cve_id = (request.get_json(silent=True) or {}).get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id is required"}), 400
    starter = str(AI_ENGINE_DIR)
    if starter not in sys.path:
        sys.path.insert(0, starter)
    try:
        from scheduled_agent import review
        result = review.approve(cve_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(result), (200 if result.get("ok") else 404)


@app.route("/api/cve-agent/reject", methods=["POST"])
def cve_agent_reject():
    cve_id = (request.get_json(silent=True) or {}).get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id is required"}), 400
    starter = str(AI_ENGINE_DIR)
    if starter not in sys.path:
        sys.path.insert(0, starter)
    try:
        from scheduled_agent import review
        result = review.reject(cve_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(result), (200 if result.get("ok") else 404)


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
