#!/usr/bin/env bash
# Deployment preflight for the Wazuh AI Threat Engine.
# Read-only checks that turn the DEPLOYMENT.md blocking checklist into a gate.
# Exit 0 = ready to expose; non-zero = at least one blocking check failed.
#
#   ./preflight.sh                       # uses /etc/wazuh-ai/backend.env if present
#   ENV_FILE=./my.env ./preflight.sh     # check a specific env file
#   BASE_URL=http://127.0.0.1:5000 ./preflight.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE="$REPO/services/ai-engine"
BACKEND="$REPO/apps/backend"
VENV="$ENGINE/venv"
ENV_FILE="${ENV_FILE:-/etc/wazuh-ai/backend.env}"
BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"

fail=0; warn=0
ok(){   printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad(){  printf '  \033[31m✗ %s\033[0m\n' "$1"; fail=$((fail+1)); }
note(){ printf '  \033[33m! %s\033[0m\n' "$1"; warn=$((warn+1)); }
hdr(){  printf '\n\033[1m%s\033[0m\n' "$1"; }

hdr "1. Secrets & environment"
if [[ -f "$ENV_FILE" ]]; then
  ok "env file present: $ENV_FILE"
  if grep -q "CHANGE_ME" "$ENV_FILE"; then
    bad "env still contains CHANGE_ME placeholders (FLASK_SECRET_KEY / ADMIN_PASSWORD / PG_PASSWORD)"
  else
    ok "no CHANGE_ME placeholders left"
  fi
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE" 2>/dev/null; set +a
  [[ "${AUTH_ENABLED:-1}" == "1" ]] && ok "AUTH_ENABLED=1" || bad "AUTH_ENABLED is not 1 — endpoints would be open"
  case "${ALLOWED_ORIGINS:-}" in
    *yourdomain*|"" ) note "ALLOWED_ORIGINS not set to a real domain (CORS)";;
    * ) ok "ALLOWED_ORIGINS=$ALLOWED_ORIGINS";;
  esac
  [[ "${AUTH_COOKIE_SECURE:-0}" == "1" ]] && ok "AUTH_COOKIE_SECURE=1 (set once HTTPS is live)" \
    || note "AUTH_COOKIE_SECURE!=1 — enable once TLS is in front"
  # Behind a proxy the login lockout / rate limits must key on the visitor IP,
  # not on 127.0.0.1 — one attacker would otherwise lock out every account.
  case "${ALLOWED_ORIGINS:-}" in
    https://* ) [[ "${TRUST_PROXY:-0}" == "1" ]] \
        && ok "TRUST_PROXY=1 (real client IPs behind nginx/Cloudflare)" \
        || bad "TRUST_PROXY!=1 while serving over HTTPS — rate limits and the login lockout would see only the proxy IP";;
    * ) [[ "${TRUST_PROXY:-0}" == "1" ]] \
        && note "TRUST_PROXY=1 without a proxy in front — X-Forwarded-For is caller-controlled" \
        || ok "TRUST_PROXY=0 (direct exposure — correct without a proxy)";;
  esac
else
  note "no env file at $ENV_FILE (set ENV_FILE=… or copy infra/deploy/wazuh-ai-backend.env)"
fi

hdr "2. No hardcoded secrets in source"
if grep -rInE "sk_(live|test)_[A-Za-z0-9]{8}" "$BACKEND"/*.py "$ENGINE"/*.py >/dev/null 2>&1; then
  bad "possible Stripe key literal in source"
else
  ok "no Stripe key literals in source"
fi

hdr "3. Python environment (pinned)"
if [[ -x "$VENV/bin/python" ]]; then
  ok "venv present"
  if "$VENV/bin/python" - <<'PY' 2>/dev/null
import importlib
for m in ("flask","waitress","sklearn","numpy","joblib","qdrant_client",
          "requests","psycopg2","stripe"):
    importlib.import_module(m)
PY
  then ok "core imports resolve (flask, waitress, sklearn, qdrant, stripe, …)"
  else bad "core imports failed — run: $VENV/bin/pip install -r $ENGINE/requirements.lock"
  fi
else
  bad "venv missing — python3 -m venv $VENV && $VENV/bin/pip install -r $ENGINE/requirements.lock"
fi

hdr "4. Trained models present"
MODELS_DIR="${AI_MODELS_DIR:-/var/ossec/ai_models}"
[[ -d "$MODELS_DIR" ]] || MODELS_DIR="$ENGINE/data/ai_models"
need=(anomaly_detector.pkl autoencoder_model.pkl ueba_model.pkl stacking_meta.pkl)
miss=0
for m in "${need[@]}"; do [[ -f "$MODELS_DIR/$m" ]] || { note "missing model: $MODELS_DIR/$m"; miss=$((miss+1)); }; done
[[ $miss -eq 0 ]] && ok "all four models found in $MODELS_DIR" \
  || note "train/promote models before serving (retrain_all.sh); ensemble degrades gracefully otherwise"

hdr "5. Data services"
if command -v docker >/dev/null 2>&1; then
  docker ps --format '{{.Names}}' 2>/dev/null | grep -q qdrant   && ok "Qdrant container up"   || note "Qdrant container not detected (docker compose up -d)"
  docker ps --format '{{.Names}}' 2>/dev/null | grep -q postgres && ok "Postgres container up" || note "Postgres container not detected"
else
  note "docker not on PATH — skipping container checks"
fi
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
if curl -sf --max-time 4 "$OLLAMA_URL/api/tags" >/dev/null 2>&1; then
  ok "Ollama reachable at $OLLAMA_URL"
  curl -s --max-time 4 "$OLLAMA_URL/api/tags" | grep -q "${OLLAMA_MODEL:-llama3.2}" \
    && ok "model ${OLLAMA_MODEL:-llama3.2} pulled" || note "pull the model: ollama pull ${OLLAMA_MODEL:-llama3.2}"
else
  note "Ollama not reachable at $OLLAMA_URL (ollama serve & + ollama pull llama3.2)"
fi

hdr "6. Live server (if running)"
if curl -sf --max-time 4 "$BASE_URL/health" >/dev/null 2>&1; then
  ok "/health OK"
  r=$(curl -s --max-time 20 "$BASE_URL/ready")
  echo "$r" | grep -q '"status":"ready"' && ok "/ready OK — $r" || bad "/ready not ready — $r"
else
  note "server not responding at $BASE_URL/health (not started yet — fine before install)"
fi

hdr "Result"
if [[ $fail -eq 0 ]]; then
  printf '  \033[32mPREFLIGHT PASSED\033[0m (%d warnings)\n' "$warn"
  echo "  Warnings are non-blocking; review them before going public."
  exit 0
else
  printf '  \033[31mPREFLIGHT FAILED — %d blocking issue(s), %d warnings\033[0m\n' "$fail" "$warn"
  echo "  Fix the ✗ items before exposing the app."
  exit 1
fi
