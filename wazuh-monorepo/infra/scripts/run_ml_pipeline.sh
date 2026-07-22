#!/usr/bin/env bash
# ML retraining + testing pipeline — run by Jenkins (host agent) or manually.
#
#   ./run_ml_pipeline.sh            train all models, evaluate, push metrics
#   SKIP_TRAIN=1 ./run_ml_pipeline.sh   evaluate + push only
#   PUSHGATEWAY=http://localhost:9091   (default) where metrics go
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STARTER="$REPO_DIR/services/ai-engine"
PY="$STARTER/venv/bin/python3"
PUSHGATEWAY="${PUSHGATEWAY:-http://localhost:9091}"

cd "$STARTER"

if [[ "${SKIP_TRAIN:-0}" != "1" ]]; then
  echo "=== [1/6] Train Isolation Forest (unsupervised, all data) ==="
  "$PY" train_isolation_forest.py

  echo "=== [2/6] Train Autoencoder (one-class, clean data + self-trim) ==="
  "$PY" autoencoders_approach/train_autoencoder.py

  echo "=== [3/6] Build UEBA baselines (clean data) ==="
  "$PY" train_ueba.py

  echo "=== [4/6] Train stacking meta-model (learned weights) ==="
  "$PY" train_stacking.py
else
  echo "=== SKIP_TRAIN=1 — evaluation only ==="
fi

echo "=== [5/6] Evaluate all models on held-out test set ==="
"$PY" "$SCRIPT_DIR/ml_eval_metrics.py" --out "$STARTER/data/eval/ml_metrics.json"

echo "=== [6/6] Push metrics to Prometheus Pushgateway ==="
"$PY" "$SCRIPT_DIR/push_metrics.py" --kind ml \
  --file "$STARTER/data/eval/ml_metrics.json" --gateway "$PUSHGATEWAY" \
  || echo "[warn] Pushgateway unreachable at $PUSHGATEWAY — metrics kept in data/eval/"

echo "=== Done ==="
