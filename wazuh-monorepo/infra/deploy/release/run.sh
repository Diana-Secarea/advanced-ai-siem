#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Selenne — launcher (Linux)
#
#  Starts the Selenne backend + dashboard on http://127.0.0.1:5000.
#  Run ./install.sh once first. No root required.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
AI="$PWD/app/services/ai-engine"
BACKEND="$PWD/app/apps/backend"
VENV="$AI/venv"

if [ ! -x "$VENV/bin/python" ]; then
    echo "Selenne isn't set up yet — run ./install.sh first." >&2
    exit 1
fi

# Bring the Docker services up if they're installed but not running (best effort).
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "$AI/docker-compose.yml" up -d >/dev/null 2>&1 || true
fi

export BIND_HOST="${BIND_HOST:-127.0.0.1}"
export BIND_PORT="${BIND_PORT:-5000}"

printf '\033[1;36mSelenne → http://%s:%s   (Ctrl+C to stop)\033[0m\n' "$BIND_HOST" "$BIND_PORT"
cd "$BACKEND"
exec "$VENV/bin/python" wsgi.py
