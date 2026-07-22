#!/bin/bash
# Start the Wazuh AI backend.
# Ensures Qdrant + Postgres (Docker) are up, then launches the Flask server.
# Needs sudo to read /var/ossec/logs/alerts/alerts.log.

set -e
# Resolve the REAL script location (works through the compat symlinks too,
# e.g. when invoked from the old ~/wazuh/backend path)
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

VENV="../../services/ai-engine/venv"
COMPOSE="../../services/ai-engine/docker-compose.yml"

# ── 1. venv check ──────────────────────────────────────────────────────────
if [[ ! -d "$VENV" ]]; then
    echo "[ERROR] venv not found at $VENV"
    echo "  Run: cd ../../services/ai-engine && python3 -m venv venv && venv/bin/pip install -r requirements.txt"
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
export OLLAMA_KEEP_ALIVE=24h
if ! pgrep -x ollama > /dev/null; then
    echo "      Starting Ollama in background (keep_alive=24h)..."
    ollama serve &>/tmp/ollama.log &
    sleep 2
else
    echo "      Ollama already running."
fi
# Warm-up: load the model into VRAM now and pin it for 24h, so the first
# chat request doesn't pay the cold-load cost. Works even if Ollama was
# already running without OLLAMA_KEEP_ALIVE set.
echo "      Warming up llama3.2 (pin in VRAM for 24h)..."
curl -s http://localhost:11434/api/generate \
    -d '{"model":"llama3.2","prompt":"","keep_alive":"24h"}' > /dev/null || \
    echo "      [WARN] Warm-up failed — model will load on first request."

# ── 4. Backend server ──────────────────────────────────────────────────────
# Production: waitress WSGI server (wsgi.py). Set DEV_SERVER=1 to use the
# Flask dev server instead (auto-reload, single-purpose — not for production).
ENTRY="wsgi.py"; MODE="waitress (production)"
if [[ "${DEV_SERVER:-0}" == "1" ]]; then ENTRY="server.py"; MODE="Flask dev server"; fi
echo "[3/3] Starting backend — $MODE (sudo for alert log access)..."
echo ""
echo "  Dashboard : http://127.0.0.1:5000"
echo "  Health    : http://127.0.0.1:5000/health   ·   Ready: /ready"
echo "  Chat UI   : http://127.0.0.1:5000/chat.html"
echo ""
exec sudo -E "$VENV/bin/python" "$ENTRY"
