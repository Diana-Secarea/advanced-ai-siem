#!/usr/bin/env bash
# Wire the Selenne backend's logs into the Wazuh manager: install the rule file,
# add the <localfile> entries, validate, restart.
#
#   sudo bash install-selenne-logging.sh              # uses /etc/wazuh-ai/backend.env
#   sudo env ENV_FILE=./my.env bash install-selenne-logging.sh
#   sudo bash install-selenne-logging.sh --dry-run    # show what would change
#
# Idempotent: re-running when everything is already in place makes no changes,
# validates nothing and restarts nothing. Safe from bootstrap-server.sh or by
# hand, and safe to run again after a Wazuh upgrade rewrites ossec.conf.
#
# The paths come from the backend's own env file, because the two halves have to
# agree: a <localfile> pointing at a path the backend does not write is exactly
# how the dead /var/log/flask_access.log entry sat in ossec.conf from May 2026
# with nothing behind it and nothing looking wrong.
set -euo pipefail

OSSEC="${OSSEC_DIR:-/var/ossec}"
ENV_FILE="${ENV_FILE:-/etc/wazuh-ai/backend.env}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

changed=0
ok(){   printf '  \033[32m✓\033[0m %s\n' "$1"; }
add(){  printf '  \033[36m+\033[0m %s\n' "$1"; changed=1; }
note(){ printf '  \033[33m!\033[0m %s\n' "$1"; }
die(){  printf '  \033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

[[ -d "$OSSEC" ]] || die "no Wazuh install at $OSSEC — install wazuh-manager first (set OSSEC_DIR= to override)"
CONF="$OSSEC/etc/ossec.conf"
[[ -f "$CONF" ]] || die "$CONF not found"
# What this actually needs is write access to ossec.conf — EUID is only a proxy
# for that. Checking the real thing keeps --dry-run usable unprivileged, so an
# operator can preview the change before handing it a root shell.
if (( ! DRY )) && [[ ! -w "$CONF" ]]; then
  die "cannot write $CONF — re-run with sudo, or pass --dry-run to preview"
fi
[[ -x "$OSSEC/bin/wazuh-analysisd" ]] \
  || die "$OSSEC/bin/wazuh-analysisd missing — this looks like an agent, not a manager; the rules only work on the manager"

# ── Paths: resolved exactly as preflight.sh resolves them ────────────────────
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE" 2>/dev/null; set +a
  ok "env: $ENV_FILE"
else
  note "no env file at $ENV_FILE — falling back to the repo defaults, which is"
  note "  almost certainly wrong for a systemd deployment (set ENV_FILE=…)"
fi
AUDIT_LOG="${AUDIT_LOG:-${LOG_DIR:-$REPO/apps/backend/logs}/selenne-audit.json}"
ACCESS_LOG="${ACCESS_LOG:-${LOG_DIR:-$REPO/apps/backend/logs}/flask_access.log}"

printf '\n\033[1mSelenne → Wazuh logging\033[0m\n'
printf '  audit  (json)   %s\n' "$AUDIT_LOG"
printf '  access (apache) %s\n' "$ACCESS_LOG"
printf '\n'

# ── 1. Log directory the backend has to be able to write ────────────────────
LOG_OWNER="${LOG_OWNER:-root}"
# Deduped: both logs usually share one directory, and reporting it twice reads
# like two separate changes.
for d in $(printf '%s\n%s\n' "$(dirname "$AUDIT_LOG")" "$(dirname "$ACCESS_LOG")" | sort -u); do
  if [[ -d "$d" ]]; then
    ok "log dir exists: $d"
  elif (( DRY )); then
    add "would create $d (owner $LOG_OWNER)"
  else
    install -d -o "$LOG_OWNER" -g "$LOG_OWNER" -m 750 "$d"
    add "created $d (owner $LOG_OWNER)"
  fi
done

# ── 2. Rule file ────────────────────────────────────────────────────────────
SRC_RULES="$HERE/selenne_rules.xml"
DST_RULES="$OSSEC/etc/rules/selenne_rules.xml"
[[ -f "$SRC_RULES" ]] || die "$SRC_RULES missing"
if [[ -f "$DST_RULES" ]] && cmp -s "$SRC_RULES" "$DST_RULES"; then
  ok "rules up to date: $DST_RULES"
elif (( DRY )); then
  add "would install $DST_RULES"
else
  install -m 660 -o wazuh -g wazuh "$SRC_RULES" "$DST_RULES" 2>/dev/null \
    || install -m 660 "$SRC_RULES" "$DST_RULES"
  add "installed $DST_RULES"
fi

# ── 3. <localfile> entries ──────────────────────────────────────────────────
# Appended as a new <ossec_config> section rather than spliced into an existing
# one: ossec.conf is a concatenation of root sections, so appending cannot
# corrupt what is already there, and a Wazuh upgrade that rewrites the original
# section leaves ours intact.
pending=""
for pair in "json:$AUDIT_LOG" "apache:$ACCESS_LOG"; do
  fmt="${pair%%:*}"; path="${pair#*:}"
  n=$(grep -cF "<location>$path</location>" "$CONF" || true)
  if (( n == 1 )); then
    ok "already collected: $path"
    continue
  elif (( n > 1 )); then
    # Not fatal, but it means Wazuh tails the file n times and every event
    # alerts n times. Flagged rather than auto-removed: deleting config the
    # operator may have put there by hand is not this script's call.
    note "$path appears $n times in ossec.conf — Wazuh will read it $n times and"
    note "  every event will alert $n times; remove the duplicates by hand"
    continue
  fi
  pending+="  <localfile>
    <log_format>$fmt</log_format>
    <location>$path</location>
  </localfile>
"
  add "will collect ($fmt): $path"
done

if [[ -z "$pending" && $changed -eq 0 ]]; then
  printf '\n\033[32mNothing to do — already wired.\033[0m\n'
  exit 0
fi

if (( DRY )); then
  [[ -n "$pending" ]] && { printf '\nWould append to %s:\n\n<ossec_config>\n%s</ossec_config>\n' "$CONF" "$pending"; }
  printf '\n\033[33mDry run — nothing written.\033[0m\n'
  exit 0
fi

BACKUP=""
if [[ -n "$pending" ]]; then
  BACKUP="$CONF.bak-selenne-$(date +%Y%m%d%H%M%S)"
  cp -a "$CONF" "$BACKUP"
  ok "backed up ossec.conf → $BACKUP"
  printf '\n<ossec_config>\n  <!-- Selenne backend logs — added by install-selenne-logging.sh.\n       Paths must match AUDIT_LOG / ACCESS_LOG in the backend env. -->\n%s</ossec_config>\n' \
    "$pending" >> "$CONF"
fi

# ── 4. Validate BEFORE restarting ───────────────────────────────────────────
# A bad ossec.conf makes the manager fail to come back up, which takes the whole
# alert pipeline down. Test first, roll back on failure, never restart blind.
printf '\n  validating configuration…\n'
if out=$("$OSSEC/bin/wazuh-analysisd" -t 2>&1); then
  ok "wazuh-analysisd -t passed"
else
  printf '%s\n' "$out" | sed 's/^/      /'
  if [[ -n "$BACKUP" ]]; then
    cp -a "$BACKUP" "$CONF"
    note "restored $CONF from the backup — the manager was NOT restarted"
  fi
  die "configuration test failed (see above); nothing was applied"
fi

# ── 5. Restart, then confirm the file is really being read ──────────────────
printf '\n  restarting the manager…\n'
# Only the default install is the one systemd knows about. With OSSEC_DIR
# pointed elsewhere, `systemctl restart wazuh-manager` would restart the real
# manager rather than the tree being configured, so drive that one directly.
if [[ "$OSSEC" == "/var/ossec" ]] && systemctl restart wazuh-manager 2>/dev/null; then
  ok "wazuh-manager restarted (systemd)"
else
  "$OSSEC/bin/wazuh-control" restart >/dev/null \
    || die "manager failed to restart — check $OSSEC/logs/ossec.log"
  ok "manager restarted ($OSSEC/bin/wazuh-control)"
fi

# The last half nobody checks: analysisd accepting the config does not mean
# logcollector opened the file. It says so in ossec.log when it does.
sleep 3
for pair in "json:$AUDIT_LOG" "apache:$ACCESS_LOG"; do
  path="${pair#*:}"
  if grep -qF "Analyzing file: '$path'" "$OSSEC/logs/ossec.log" 2>/dev/null; then
    ok "logcollector opened $path"
  elif [[ ! -e "$path" ]]; then
    note "$path does not exist yet — logcollector will pick it up once the backend writes it"
  else
    note "no 'Analyzing file: $path' in ossec.log yet — check $OSSEC/logs/ossec.log"
  fi
done

printf '\n\033[32mDone.\033[0m Verify with: sudo env ENV_FILE=%s bash %s\n' \
  "$ENV_FILE" "$REPO/infra/deploy/preflight.sh"
