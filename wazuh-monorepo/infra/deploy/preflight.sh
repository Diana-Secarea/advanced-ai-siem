#!/usr/bin/env bash
# Deployment preflight for the Wazuh AI Threat Engine.
# Read-only checks that turn the DEPLOYMENT.md blocking checklist into a gate.
# Exit 0 = ready to expose; non-zero = at least one blocking check failed.
#
#   ./preflight.sh                       # uses /etc/wazuh-ai/backend.env if present
#   ENV_FILE=./my.env ./preflight.sh     # check a specific env file
#   BASE_URL=http://127.0.0.1:5000 ./preflight.sh
#
# Reading ossec.conf and authd.pass needs root, and sudo strips the environment:
#   ENV_FILE=./my.env sudo ./preflight.sh    # WRONG — silently checks the default
#   sudo env ENV_FILE=./my.env ./preflight.sh  # right
# Run unprivileged and the manager-side halves degrade to warnings, never to a
# false pass.
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

  # Required and non-empty. The CHANGE_ME grep above only catches a placeholder
  # someone left behind — it says nothing about a variable that was never added
  # to the file at all. That gap is not theoretical: WAZUH_REG_PASSWORD was
  # missing from the env template entirely, so every /api/download/agent/*
  # request returned 503 and this gate stayed green.
  for _v in FLASK_SECRET_KEY ADMIN_PASSWORD PG_PASSWORD \
            WAZUH_REG_PASSWORD SELENNE_MANAGER_HOST SELENNE_DASHBOARD_HOST; do
    if [[ -z "${!_v:-}" ]]; then
      case "$_v" in
        WAZUH_REG_PASSWORD)
          bad "$_v unset — every collector download returns 503 (nobody can enrol an endpoint)";;
        SELENNE_MANAGER_HOST)
          bad "$_v unset — installers would take the manager address from the caller's Host header";;
        SELENNE_DASHBOARD_HOST)
          bad "$_v unset — installer text and the Start Menu shortcut would point at the caller's Host header";;
        *)
          bad "$_v unset in $ENV_FILE";;
      esac
    else
      ok "$_v set"
    fi
  done
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

  # The OTHER half of the pair: nginx must actually write the visitor IP.
  # TRUST_PROXY=1 with no real_ip_header silently buckets by Cloudflare edge
  # node instead of by visitor — checking only the backend half is what let
  # the live host drift for weeks without anything looking wrong.
  if [[ "${TRUST_PROXY:-0}" == "1" ]]; then
    if ! cat /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* >/dev/null 2>&1; then
      note "cannot read /etc/nginx — re-run with sudo to check the nginx half"
    elif grep -rq "^[[:space:]]*real_ip_header" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null; then
      ok "nginx restores the real client IP (real_ip_header present)"
    else
      bad "TRUST_PROXY=1 but no real_ip_header in nginx — every visitor still shares one rate-limit/lockout counter (run ./cloudflare-realip.sh)"
    fi
  fi

  # The OTHER half again: the backend can write a perfect audit log and the
  # console still shows nothing, because whether an event becomes an alert is
  # decided by ossec.conf, not by the backend. Checking only the backend half
  # is how /var/log/flask_access.log sat in ossec.conf for months while nothing
  # wrote it and nobody noticed.
  _audit_log="${AUDIT_LOG:-${LOG_DIR:-$BACKEND/logs}/selenne-audit.json}"
  _access_log="${ACCESS_LOG:-${LOG_DIR:-$BACKEND/logs}/flask_access.log}"
  if [[ -r /var/ossec/etc/ossec.conf ]]; then
    for _pair in "audit:$_audit_log" "access:$_access_log"; do
      _kind="${_pair%%:*}"; _path="${_pair#*:}"
      _n=$(grep -cF "<location>$_path</location>" /var/ossec/etc/ossec.conf || true)
      if (( _n == 1 )); then
        ok "$_kind log $_path is collected by Wazuh"
      elif (( _n > 1 )); then
        # Two <localfile> entries for one path means the file is tailed twice
        # and every event alerts twice — a real duplicate-alert source, and the
        # live ossec.conf has exactly this for flask_access.log.
        note "$_kind log $_path has $_n <localfile> entries — Wazuh tails it $_n times, so every event alerts $_n times"
      else
        bad "$_kind log goes to $_path, which no <localfile> in ossec.conf reads — those events never reach the console (fix: sudo env ENV_FILE=$ENV_FILE bash infra/deploy/wazuh/install-selenne-logging.sh)"
      fi
    done
    if [[ -f /var/ossec/etc/rules/selenne_rules.xml ]]; then
      if cmp -s "$REPO/infra/deploy/wazuh/selenne_rules.xml" /var/ossec/etc/rules/selenne_rules.xml; then
        ok "selenne_rules.xml installed and matches the repo"
      else
        # Installed but stale: the alerts that fire are the old file's, which is
        # worse than missing because the gate looks green.
        note "selenne_rules.xml differs from infra/deploy/wazuh/selenne_rules.xml — re-run install-selenne-logging.sh to update it"
      fi
    else
      bad "/var/ossec/etc/rules/selenne_rules.xml missing — audit events decode but match no rule, so no alert is raised (fix: infra/deploy/wazuh/install-selenne-logging.sh)"
    fi
  else
    note "cannot read /var/ossec/etc/ossec.conf — re-run with sudo to check the collector half"
  fi
  # Signup completeness. Registration is open to the internet, and a new
  # account is unverified until it opens an emailed link — so with no mail
  # transport every self-service signup dead-ends and no customer can ever
  # reach a download.
  if [[ -z "${SMTP_HOST:-}" ]]; then
    bad "SMTP_HOST unset — verification mail cannot be sent, so no self-registered account can ever download a collector"
  else
    ok "SMTP_HOST=$SMTP_HOST (verification mail can be sent)"
  fi
  case "${SELENNE_PUBLIC_URL:-}" in
    https://*) ok "SELENNE_PUBLIC_URL=$SELENNE_PUBLIC_URL" ;;
    "")  bad "SELENNE_PUBLIC_URL unset — verification mail would carry a bare token instead of a working link" ;;
    *)   note "SELENNE_PUBLIC_URL=$SELENNE_PUBLIC_URL is not https — verification links will not be secure" ;;
  esac

  # Enrolment, both halves. A password in the env proves only that installers
  # carry one — the manager decides whether it is DEMANDED. Shipped as found:
  # use_password was "no" with no authd.pass at all, so every download looked
  # fine and enrolment on 1515 was open to anyone who could reach the port.
  if [[ -r /var/ossec/etc/ossec.conf ]]; then
    _authd_use=$(sed -n '/<auth>/,/<\/auth>/p' /var/ossec/etc/ossec.conf \
                 | grep -o '<use_password>[^<]*' | cut -d'>' -f2)
    if [[ "$_authd_use" != "yes" ]]; then
      bad "manager has <use_password>${_authd_use:-unset}</use_password> — enrolment on 1515 accepts anyone, the installer password is not checked"
    elif [[ ! -r /var/ossec/etc/authd.pass ]]; then
      note "use_password=yes but authd.pass unreadable here — re-run with sudo to compare it with WAZUH_REG_PASSWORD"
    elif [[ "$(tr -d '\r\n' < /var/ossec/etc/authd.pass)" == "${WAZUH_REG_PASSWORD:-}" ]]; then
      ok "enrolment password required by the manager and matches WAZUH_REG_PASSWORD"
    else
      bad "WAZUH_REG_PASSWORD does not match /var/ossec/etc/authd.pass — every generated installer fails at enrolment"
    fi
  else
    note "cannot read /var/ossec/etc/ossec.conf — re-run with sudo to check the enrolment half"
  fi

  # The manager host must NOT be proxied. Agent traffic is raw TCP on 1514/1515;
  # Cloudflare's edge answers 80/443 only, so a proxied name turns every
  # enrolment into a timeout while the dashboard keeps working perfectly.
  if [[ -n "${SELENNE_MANAGER_HOST:-}" ]]; then
    _mgr_ips=$(getent ahostsv4 "$SELENNE_MANAGER_HOST" 2>/dev/null | awk '{print $1}' | sort -u)
    if [[ -z "$_mgr_ips" ]]; then
      bad "SELENNE_MANAGER_HOST=$SELENNE_MANAGER_HOST does not resolve — collectors cannot find the manager"
    elif grep -qE '^(104\.(1[6-9]|2[0-7])\.|172\.6[4-9]\.|172\.7[0-1]\.|188\.114\.9[6-7]\.|162\.159\.|198\.41\.12[8-9]\.|173\.245\.4[89]\.|103\.21\.24[4-7]\.)' <<<"$_mgr_ips"; then
      bad "SELENNE_MANAGER_HOST=$SELENNE_MANAGER_HOST resolves to Cloudflare ($(tr '\n' ' ' <<<"$_mgr_ips")) — 1515/1514 are raw TCP and the proxy does not forward them; use a DNS-only (grey-cloud) record"
    else
      ok "SELENNE_MANAGER_HOST=$SELENNE_MANAGER_HOST resolves past the proxy"
    fi
  fi
  if [[ -n "${SELENNE_DASHBOARD_HOST:-}" && "${SELENNE_DASHBOARD_HOST:-}" == "${SELENNE_MANAGER_HOST:-}" ]]; then
    note "SELENNE_DASHBOARD_HOST equals SELENNE_MANAGER_HOST — one name cannot be both proxied (dashboard) and direct (agents)"
  fi

else
  note "no env file at $ENV_FILE (set ENV_FILE=… or copy infra/deploy/wazuh-ai-backend.env.example)"
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
