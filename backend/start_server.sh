#!/bin/bash
# Start the Wazuh AI backend.
# Ensures Qdrant + Postgres (Docker) are up, then launches the Flask server.
# Needs sudo to read /var/ossec/logs/alerts/alerts.log.

set -e
cd "$(dirname "$0")"

VENV="../ai_threat_engine_starter/venv"
COMPOSE="../ai_threat_engine_starter/docker-compose.yml"

# ── 1. venv check ──────────────────────────────────────────────────────────
if [[ ! -d "$VENV" ]]; then
    echo "[ERROR] venv not found at $VENV"
    echo "  Run: cd ../ai_threat_engine_starter && python3 -m venv venv && venv/bin/pip install -r requirements.txt"
    exit 1
fi

# ── 2. Docker containers (Qdrant + Postgres) ───────────────────────────────
echo "[1/3] Checking Docker containers..."
if ! docker compose -f "$COMPOSE" ps --status running | grep -q "wazuh_qdrant"; then
    echo "      Starting Qdrant + Postgres..."
    docker compose -f "$COMPOSE" up -d
    echo "      Waiting for containers to be healthy..."
    sleep 5
else
    echo "      Qdrant + Postgres already running."
fi

# ── 3. Ollama ──────────────────────────────────────────────────────────────
echo "[2/3] Checking Ollama..."
if ! pgrep -x ollama > /dev/null; then
    echo "      Starting Ollama in background..."
    ollama serve &>/tmp/ollama.log &
    sleep 2
else
    echo "      Ollama already running."
fi

# ── 4. Flask server ────────────────────────────────────────────────────────
echo "[3/3] Starting Flask server (sudo for alert log access)..."
echo ""
echo "  Dashboard : http://127.0.0.1:5000"
echo "  Chat UI   : http://127.0.0.1:5000/chat.html"
echo ""
exec sudo "$VENV/bin/python" server.py
