#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Build the downloadable Selene release: infra/deploy/dist/selene-linux.tar.gz
#
#  Bundles the app source + trained models + installer, EXCLUDING virtualenvs,
#  caches, and every secret/stateful file (.env, users.db, *.jsonl, vector data).
#  A hard secret-guard aborts the build if anything sensitive slips in.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.."   # -> wazuh-monorepo
MONO="$PWD"
REL="$MONO/infra/deploy/release"
DIST="$MONO/infra/deploy/dist"
NAME="selene-linux"
STAGE="$(mktemp -d)"
APP="$STAGE/$NAME/app"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$APP/apps" "$APP/services" "$APP/infra" "$DIST"

# Global excludes: environments, caches, VCS, and anything secret/stateful.
EXCL=(
    --exclude 'venv' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc'
    --exclude '.git' --exclude '.git/**' --exclude 'node_modules'
    --exclude '.env' --exclude '.env.local' --exclude '.env.*.local'
    --exclude 'users.db' --exclude '*.jsonl' --exclude '*.log' --exclude 'logs'
    --exclude 'data/chats' --exclude 'chats'   # private per-user RAG conversations
    --exclude '.DS_Store'
)

echo "→ staging app source…"
rsync -a "${EXCL[@]}" "$MONO/apps/backend"  "$APP/apps/"
rsync -a "${EXCL[@]}" "$MONO/apps/frontend" "$APP/apps/"
# ai-engine: keep code + requirements + docker-compose + trained models; drop the
# heavy/regenerable data (vector index, eval corpora, training sets, raw alerts).
rsync -a "${EXCL[@]}" \
    --exclude 'data/vector_db' --exclude 'data/eval' --exclude 'data/eval_reports' \
    --exclude 'data/test' --exclude 'data/training' --exclude 'data/blindspots' \
    --exclude 'data/alerts.json' \
    "$MONO/services/ai-engine" "$APP/services/"
[ -f "$MONO/infra/docker-compose.yml" ] && cp "$MONO/infra/docker-compose.yml" "$APP/infra/"

echo "→ adding installer + docs…"
cp "$REL/install.sh" "$REL/run.sh" "$REL/README_INSTALL.md" "$STAGE/$NAME/"
chmod +x "$STAGE/$NAME/install.sh" "$STAGE/$NAME/run.sh"

# ── HARD SECRET GUARD ───────────────────────────────────────────────────────
LEAKED="$(find "$STAGE/$NAME" \( -name '.env' -o -name '.env.local' \
            -o -name 'users.db' -o -name '*.jsonl' -o -path '*/data/chats/*' \) 2>/dev/null || true)"
if [ -n "$LEAKED" ]; then
    echo "ABORT: secret/stateful file(s) staged for release:" >&2
    echo "$LEAKED" >&2
    exit 1
fi

echo "→ compressing…"
tar -czf "$DIST/$NAME.tar.gz" -C "$STAGE" "$NAME"
echo "✔ built $DIST/$NAME.tar.gz ($(du -h "$DIST/$NAME.tar.gz" | cut -f1))"
