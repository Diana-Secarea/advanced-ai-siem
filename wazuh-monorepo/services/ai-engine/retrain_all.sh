#!/usr/bin/env bash
# Retrain the full detection pipeline in the required order and refresh
# everything that depends on it. Safe to run monthly (or whenever
# monitor_model_health.py reports PSI drift).
#
# Suggested cron (1st of each month, 03:00):
#   0 3 1 * * cd /home/sek/wazuh/wazuh-monorepo/services/ai-engine && ./retrain_all.sh >> data/eval/retrain.log 2>&1
#
# Note: the running backend keeps the OLD models in memory — restart it
# after this script finishes to pick up the new pkls.
set -euo pipefail
cd "$(dirname "$0")"
PY=./venv/bin/python3

echo "=== retrain_all $(date -Is) ==="

echo "--- 1/6 collect latest alerts (dedup merge) ---"
$PY collect_training_data.py

echo "--- 2/6 Isolation Forest ---"
$PY train_isolation_forest.py

echo "--- 3/6 Autoencoder ---"
$PY autoencoders_approach/train_autoencoder.py

echo "--- 4/6 UEBA baselines ---"
$PY train_ueba.py

echo "--- 5/7 Stacking meta-model (Wazuh alerts) ---"
$PY train_stacking.py

echo "--- 6/7 Raw-log content model (non-Wazuh collector logs) ---"
# Trains the behavioural content model + honest held-out threshold for scoring
# raw system logs (journald/sshd/kernel/apache…) that carry no Wazuh alert.
$PY train_log_model.py

echo "--- 7/7 sync model copies + eval + drift reference ---"
if [ -d /var/ossec/ai_models ]; then
    cp /var/ossec/ai_models/*.pkl data/ai_models/ 2>/dev/null || true
fi
$PY ../../infra/scripts/ml_eval_metrics.py || true
$PY monitor_model_health.py --save-reference

echo "=== done $(date -Is) — restart the backend to load the new models ==="
