#!/usr/bin/env bash
# Pull (if missing) and load the Selenne chat model into memory at boot, so the
# first user request doesn't pay the cold-load cost. Run by
# ollama-warmup.service after ollama.service is up.
#
# Idempotent and safe to run by hand:
#   OLLAMA_MODEL=llama3.2 bash ollama-warmup.sh
set -uo pipefail

URL=${OLLAMA_URL:-http://127.0.0.1:11434}
MODEL=${OLLAMA_MODEL:-llama3.2}
WAIT_SECONDS=${WARMUP_WAIT_SECONDS:-120}

log() { printf '[ollama-warmup] %s\n' "$*"; }

# 1. Wait for the API. systemd starts us right after the process launches, but
#    Ollama needs a moment before it answers, and on a cold boot the disk is busy.
deadline=$((SECONDS + WAIT_SECONDS))
until curl -sf -m 3 "$URL/api/tags" >/dev/null; do
    if (( SECONDS >= deadline )); then
        log "Ollama did not answer on $URL within ${WAIT_SECONDS}s — giving up."
        exit 1
    fi
    sleep 2
done

# 2. Pull only when the model is absent: a pull on every boot would re-check the
#    registry, which fails on a host with no outbound internet.
if ! curl -sf -m 5 "$URL/api/tags" | grep -q "\"${MODEL%%:*}"; then
    log "Model '$MODEL' not present — pulling it (first boot only)."
    curl -sf -m 1800 "$URL/api/pull" -d "{\"model\":\"$MODEL\"}" >/dev/null || {
        log "Pull failed. Run: ollama pull $MODEL"
        exit 1
    }
fi

# 3. Load it into memory and keep it there. keep_alive -1 = never unload, which
#    matches OLLAMA_KEEP_ALIVE=-1 in the unit; sending it explicitly means the
#    warm-up still works if that env var is ever dropped.
log "Loading '$MODEL' into memory..."
curl -sf -m 900 "$URL/api/generate" \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"\",\"keep_alive\":-1}" >/dev/null || {
    log "Warm-up request failed — the model will load on first use instead."
    exit 1
}

log "'$MODEL' is resident and pinned."
