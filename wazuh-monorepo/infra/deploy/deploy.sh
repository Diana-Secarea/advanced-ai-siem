#!/usr/bin/env bash
# One-command deploy for the live selenne.app host, with a rollback.
#
#   ./deploy.sh              # deploy origin/main
#   ./deploy.sh --dry-run    # show what would change, touch nothing
#   ./deploy.sh --rollback   # go back to the previous deployed commit
#
# Why a script rather than "git pull && systemctl restart":
#
#  * Pull and restart must happen TOGETHER. The frontend is served straight off
#    the working tree so a pull ships pages instantly, while server.py is only
#    read at process start. On 2026-08-21 a pull without a restart broke the
#    Windows collector download for hours — the pull renamed a file the running
#    process was still looking for under its old name.
#  * A deploy that leaves the service down is worse than one that never ran.
#    This checks /ready afterwards and puts the previous commit back if the new
#    one will not come up.
#  * It records what was deployed, so a rollback is a fact rather than an
#    archaeology exercise.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MONO="$REPO/wazuh-monorepo"
UNIT="selenne-backend"
BASE_URL="${BASE_URL:-http://127.0.0.1:5000}"
STATE="$HOME/.selenne-deploy-state"
BRANCH="${BRANCH:-main}"

DRY=0; ROLLBACK=0
case "${1:-}" in
  --dry-run)  DRY=1 ;;
  --rollback) ROLLBACK=1 ;;
  "")         ;;
  *) echo "usage: $0 [--dry-run|--rollback]"; exit 2 ;;
esac

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$1"; }
note() { printf '  \033[33m! %s\033[0m\n' "$1"; }

cd "$REPO" || { bad "repo not found at $REPO"; exit 1; }

# --- restart, without needing an interactive password ----------------------
# Requires ONE narrowly-scoped sudoers rule (see DEPLOYMENT.md):
#   selenne ALL=(root) NOPASSWD: /usr/bin/systemctl restart selenne-backend
restart_service() {
  if sudo -n systemctl restart "$UNIT" 2>/dev/null; then
    return 0
  fi
  note "passwordless restart unavailable — prompting"
  sudo systemctl restart "$UNIT"
}

health_ok() {
  for _ in $(seq 1 20); do
    if curl -sf --max-time 5 "$BASE_URL/health" >/dev/null 2>&1; then
      curl -s --max-time 25 "$BASE_URL/ready" | grep -q '"status":"ready"' && return 0
    fi
    sleep 2
  done
  return 1
}

CURRENT="$(git rev-parse HEAD)"

# --- rollback ---------------------------------------------------------------
if (( ROLLBACK )); then
  PREV="$(cat "$STATE" 2>/dev/null || true)"
  [[ -n "$PREV" ]] || { bad "no previous deploy recorded in $STATE"; exit 1; }
  say "Rolling back $CURRENT -> $PREV"
  git reset --hard "$PREV" || { bad "reset failed"; exit 1; }
  restart_service
  health_ok && { ok "service healthy on $PREV"; exit 0; }
  bad "service still unhealthy after rollback — investigate by hand"
  exit 1
fi

# --- fetch and report what is about to change -------------------------------
say "Fetching origin/$BRANCH"
git fetch -q origin "$BRANCH" || { bad "fetch failed"; exit 1; }
TARGET="$(git rev-parse "origin/$BRANCH")"

if [[ "$CURRENT" == "$TARGET" ]]; then
  ok "already at $(git log --oneline -1 "$TARGET")"
  exit 0
fi

if [[ -n "$(git status --porcelain)" ]]; then
  bad "working tree is dirty — refusing to deploy over local edits:"
  git status --short | sed 's/^/      /'
  exit 1
fi

say "Incoming"
git --no-pager log --oneline "$CURRENT..$TARGET" | sed 's/^/  /'
CHANGED="$(git diff --name-only "$CURRENT..$TARGET")"
# Purely cosmetic, but it is the difference between "reload the tab" and
# "the process is running last week's code".
if grep -qE '\.py$' <<<"$CHANGED"; then
  note "Python changed — a restart is REQUIRED for this to take effect"
fi

if (( DRY )); then
  say "Dry run — nothing changed"
  exit 0
fi

# --- deploy ------------------------------------------------------------------
say "Deploying $TARGET"
git merge --ff-only "origin/$BRANCH" || {
  bad "not a fast-forward — prod has diverged from origin/$BRANCH"
  exit 1
}
ok "tree at $(git rev-parse --short HEAD)"

restart_service || { bad "restart failed"; exit 1; }

if health_ok; then
  ok "/ready reports ready"
  echo "$CURRENT" > "$STATE"          # only record a deploy that came up
  ok "rollback point recorded: ${CURRENT:0:12}"
else
  bad "service did NOT come up — rolling back to ${CURRENT:0:12}"
  git reset --hard "$CURRENT"
  restart_service
  health_ok && bad "rolled back; the new commit is broken" || bad "ROLLBACK ALSO UNHEALTHY — manual intervention needed"
  exit 1
fi

# --- post-deploy verification ------------------------------------------------
say "Preflight"
if sudo -n true 2>/dev/null; then
  sudo -n env ENV_FILE=/etc/wazuh-ai/backend.env bash "$MONO/infra/deploy/preflight.sh" || \
    note "preflight reported problems (deploy stands — review them)"
else
  note "skipped: needs sudo. Run it yourself:"
  echo "      sudo env ENV_FILE=/etc/wazuh-ai/backend.env bash infra/deploy/preflight.sh"
fi

say "Done"
git --no-pager log --oneline -1
