#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Selene — one-time installer (Linux)
#
#  Sets up the Python environment and, when available, the supporting services
#  (Qdrant + Postgres via Docker, and a local Ollama LLM). Safe to re-run.
#
#  Usage:   ./install.sh          then   ./run.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
ROOT="$PWD"
AI="$ROOT/app/services/ai-engine"
BACKEND="$ROOT/app/apps/backend"
VENV="$AI/venv"

say() { printf '\033[1;36m%s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m  [skip] %s\033[0m\n' "$*"; }

say "== Selene installer =="

# 1. Python (required) --------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required. Install it (e.g. 'sudo apt install python3 python3-venv') and re-run." >&2
    exit 1
fi
PYV="$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
say "  Python $PYV detected"

# 2. Virtual environment + dependencies --------------------------------------
if [ ! -d "$VENV" ]; then
    say "  Creating virtual environment…"
    python3 -m venv "$VENV"
fi
say "  Installing Python dependencies (may take a few minutes)…"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$AI/requirements.txt"
[ -f "$BACKEND/requirements.txt" ] && "$VENV/bin/pip" install --quiet -r "$BACKEND/requirements.txt"

# 3. Configuration ------------------------------------------------------------
if [ ! -f "$BACKEND/.env" ]; then
    cp "$BACKEND/.env.example" "$BACKEND/.env"
    say "  Wrote default config → app/apps/backend/.env (edit to add Stripe/SMTP keys if needed)"
fi

# 4. Optional services --------------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    say "  Starting Qdrant + Postgres (docker compose)…"
    docker compose -f "$AI/docker-compose.yml" up -d \
        || warn "docker compose failed — the vector DB / CVE-ledger features will be limited"
else
    warn "Docker not found — RAG vector search and the CVE ledger will be limited. Install Docker to enable them."
fi

if command -v ollama >/dev/null 2>&1; then
    MODEL="${OLLAMA_MODEL:-llama3.2}"
    say "  Pulling local LLM ($MODEL) for the AI analyst…"
    ollama pull "$MODEL" || warn "ollama pull failed — the AI chat will be unavailable until the model is present"
else
    warn "Ollama not found — the AI analyst chat needs it. Install from https://ollama.com then run: ollama pull llama3.2"
fi

echo ""
say "Done ✔  Start Selene with:   ./run.sh"
say "Then open your browser at:   http://127.0.0.1:5000"
