#!/usr/bin/env bash
# Promote model artifacts between environments.
#
#   ./promote_models.sh dev staging       dev registry  -> staging registry
#   ./promote_models.sh staging production staging      -> /var/ossec/ai_models
#
# Every promotion archives what it overwrites (rollback = copy the dated
# .bak file back). Only ever copies the four known artifacts.
set -euo pipefail

FROM="${1:?usage: promote_models.sh <dev|staging> <staging|production>}"
TO="${2:?usage: promote_models.sh <dev|staging> <staging|production>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

dir_for () {
  case "$1" in
    dev)        echo "$REPO_DIR/services/ai-engine/data/ai_models" ;;
    staging)    echo "$REPO_DIR/infra/registry/staging" ;;
    production) echo "/var/ossec/ai_models" ;;
    *) echo "unknown environment: $1" >&2; exit 1 ;;
  esac
}

SRC="$(dir_for "$FROM")"
DST="$(dir_for "$TO")"
STAMP="$(date +%Y-%m-%d_%H%M%S)"
ARTIFACTS=(anomaly_detector.pkl autoencoder_model.pkl ueba_model.pkl stacking_meta.pkl)

echo "Promoting models: $FROM ($SRC) -> $TO ($DST)"
mkdir -p "$DST"

for f in "${ARTIFACTS[@]}"; do
  if [[ ! -f "$SRC/$f" ]]; then
    echo "MISSING artifact in $FROM: $f" >&2
    exit 1
  fi
done

for f in "${ARTIFACTS[@]}"; do
  if [[ -f "$DST/$f" ]]; then
    cp "$DST/$f" "$DST/${f%.pkl}_${STAMP}.bak.pkl"
  fi
  cp "$SRC/$f" "$DST/$f"
  echo "  promoted $f"
done

# Record provenance next to the artifacts
cat > "$DST/PROMOTION.json" <<EOF
{"from": "$FROM", "to": "$TO", "at": "$STAMP", "artifacts": ["${ARTIFACTS[0]}", "${ARTIFACTS[1]}", "${ARTIFACTS[2]}", "${ARTIFACTS[3]}"]}
EOF

echo "Done. Rollback: restore *_${STAMP}.bak.pkl in $DST"
