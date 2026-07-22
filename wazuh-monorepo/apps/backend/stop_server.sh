#!/bin/bash
# Stop all Wazuh AI backend services.

cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

COMPOSE="../../services/ai-engine/docker-compose.yml"

# ── 1. Flask server ────────────────────────────────────────────────────────
echo "[1/3] Stopping Flask server..."
pkill -f "python server.py" 2>/dev/null && echo "      Stopped." || echo "      Not running."

# ── 2. Ollama ──────────────────────────────────────────────────────────────
echo "[2/3] Stopping Ollama..."
pkill -x ollama 2>/dev/null && echo "      Stopped." || echo "      Not running."

# ── 3. Docker containers ───────────────────────────────────────────────────
echo "[3/3] Stopping Qdrant + Postgres..."
docker compose -f "$COMPOSE" down
