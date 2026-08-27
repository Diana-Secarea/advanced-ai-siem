#!/usr/bin/env bash
# Model health check — is the ensemble still calibrated for THIS host?
# Run by Jenkins (host agent) daily, or manually. Requires the project venv.
#
# Deliberately NOT the same thing as run_ml_pipeline.sh: that measures the
# models against their held-out test set, this measures them against the live
# alert stream. On 2026-08-27 the first said "F1 85.7%" while the second would
# have said "the autoencoder is pinned at 100 on 88% of real traffic".
set -uo pipefail          # NOT -e: we need the health exit code, not an abort

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STARTER="$REPO_DIR/services/ai-engine"
PY="$STARTER/venv/bin/python3"
PUSHGATEWAY="${PUSHGATEWAY:-http://localhost:9091}"
ALERTS="${ALERTS_JSON:-/var/ossec/logs/alerts/alerts.json}"
OUT="$STARTER/data/eval/model_health.json"

cd "$STARTER"

echo "=== [1/2] Scoring the live alert stream ==="
"$PY" "$SCRIPT_DIR/model_health.py" --alerts "$ALERTS" --out "$OUT" \
    ${ALERT_BUDGET:+--alert-budget "$ALERT_BUDGET"} \
    ${MIN_LABEL:+--min-label "$MIN_LABEL"}
health_rc=$?

echo "=== [2/2] Push metrics to Prometheus Pushgateway ==="
# Always push, healthy or not — a dashboard that only updates on success hides
# exactly the failure it exists to show.
"$PY" "$SCRIPT_DIR/push_metrics.py" --kind health \
    --file "$OUT" --gateway "$PUSHGATEWAY" \
    || echo "[warn] Pushgateway unreachable at $PUSHGATEWAY — report kept at $OUT"

echo "=== Done (health rc=$health_rc) ==="
exit "$health_rc"
