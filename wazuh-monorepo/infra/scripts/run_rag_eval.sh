#!/usr/bin/env bash
# RAG retrieval evaluation pipeline — run by Jenkins (host agent) or manually.
# Requires Qdrant running (docker) and the project venv.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STARTER="$REPO_DIR/services/ai-engine"
PY="$STARTER/venv/bin/python3"
PUSHGATEWAY="${PUSHGATEWAY:-http://localhost:9091}"

cd "$STARTER"

echo "=== [1/2] RAG retrieval benchmark (82 queries, k=5) ==="
"$PY" "$SCRIPT_DIR/rag_eval_metrics.py" --out "$STARTER/data/eval/rag_metrics.json"

echo "=== [2/2] Push metrics to Prometheus Pushgateway ==="
"$PY" "$SCRIPT_DIR/push_metrics.py" --kind rag \
  --file "$STARTER/data/eval/rag_metrics.json" --gateway "$PUSHGATEWAY" \
  || echo "[warn] Pushgateway unreachable at $PUSHGATEWAY — metrics kept in data/eval/"

echo "=== Done ==="
