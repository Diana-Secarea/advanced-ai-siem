#!/usr/bin/env bash
# Configure outgoing mail for the backend, safely and idempotently.
#
# Verification mail is not optional any more: since the enrolment hardening, a
# self-registered account cannot download a collector until it confirms its
# address (server.py, "Verified email required"). With SMTP unset, every new
# signup registers fine and then dead-ends at a 403 — nothing logs an error,
# because nothing IS an error. This script closes that gap.
#
#   sudo ./configure-smtp.sh                     # prompts, hides the password
#   sudo ./configure-smtp.sh --test-only a@b.com # just send a test message
#
# The password is read with `read -s` rather than taken as an argument, so it
# never lands in the shell history or in `ps`. The env file is backed up before
# every change and keys are UPSERTED — run it twice and you get one copy of
# each key, not two.
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/wazuh-ai/backend.env}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV="$REPO/services/ai-engine/venv/bin/python3"
BACKEND="$REPO/apps/backend"

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }

send_test() {
  local to="$1"
  [[ -x "$VENV" ]] || { echo "venv python not found at $VENV"; return 1; }
  echo "Sending a test message to $to ..."
  ( set -a; . "$ENV_FILE"; set +a
    cd "$BACKEND"
    "$VENV" - "$to" <<'PY'
import sys
sys.path.insert(0, ".")
import mailer
if not mailer.is_configured():
    print("  FAIL: mailer reports unconfigured (SMTP_HOST empty)"); raise SystemExit(1)
ok, status = mailer.send(sys.argv[1], "Selenne SMTP test",
                         "If you are reading this, verification mail works.")
print(f"  {'OK' if ok else 'FAIL'}: {status}")
raise SystemExit(0 if ok else 1)
PY
  )
}

if [[ "${1:-}" == "--test-only" ]]; then
  [[ -n "${2:-}" ]] || { echo "usage: $0 --test-only <address>"; exit 1; }
  send_test "$2"; exit $?
fi

[[ -f "$ENV_FILE" ]] || { echo "env file not found: $ENV_FILE"; exit 1; }

echo "Configuring SMTP in $ENV_FILE"
echo "Leave a value blank to keep whatever is already set."
echo
read -r -p "  SMTP_HOST (e.g. smtp.resend.com, smtp.gmail.com) : " IN_HOST
read -r -p "  SMTP_PORT [587]                                  : " IN_PORT
read -r -p "  SMTP_USER                                        : " IN_USER
read -r -s -p "  SMTP_PASS / API key (hidden)                     : " IN_PASS; echo
# Kept separate from SMTP_USER on purpose: Resend authenticates as the literal
# string "resend", so the username is not an address and must never become one.
read -r -p "  SMTP_FROM [no-reply@selenne.app]                 : " IN_FROM
read -r -p "  SELENNE_PUBLIC_URL [https://selenne.app]         : " IN_URL

BACKUP="${ENV_FILE}.$(date +%Y-%m-%d_%H%M%S).bak"
cp -a "$ENV_FILE" "$BACKUP"
echo
echo "Backed up to $BACKUP"

upsert() {                       # upsert KEY VALUE — blank value = no change
  local key="$1" val="$2"
  [[ -n "$val" ]] || return 0
  if grep -qE "^[[:space:]]*#?[[:space:]]*${key}=" "$ENV_FILE"; then
    # Rewrites a commented-out key too, which is the usual reason a setting
    # "is in the file" and still does nothing.
    python3 - "$ENV_FILE" "$key" "$val" <<'PY'
import io, re, sys
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
lines = io.open(path, encoding="utf-8").read().splitlines(keepends=True)
out, done = [], False
for line in lines:
    if re.match(rf"^\s*#?\s*{re.escape(key)}=", line) and not done:
        out.append(f"{key}={val}\n"); done = True
    elif re.match(rf"^\s*#?\s*{re.escape(key)}=", line):
        continue                      # drop later duplicates
    else:
        out.append(line)
io.open(path, "w", encoding="utf-8").writelines(out)
PY
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
  echo "  set $key"
}

upsert SMTP_HOST "$IN_HOST"
upsert SMTP_PORT "${IN_PORT:-587}"
upsert SMTP_USER "$IN_USER"
upsert SMTP_PASS "$IN_PASS"
upsert SMTP_FROM "${IN_FROM:-no-reply@selenne.app}"
upsert SELENNE_PUBLIC_URL "${IN_URL:-https://selenne.app}"

chmod 600 "$ENV_FILE"
echo
echo "Keys now present (names only):"
grep -oE '^(SMTP_HOST|SMTP_PORT|SMTP_USER|SMTP_PASS|SMTP_FROM|SELENNE_PUBLIC_URL)=' "$ENV_FILE" | tr -d '='
echo
echo "Next:"
echo "  sudo systemctl restart selenne-backend      # the service reads env at start"
echo "  sudo $0 --test-only you@example.com         # prove a message actually sends"
