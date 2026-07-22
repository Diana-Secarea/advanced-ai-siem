#!/bin/bash
# Collect Wazuh alerts daily for Isolation Forest training.
#
# Usage:
#   Manual:   ./collect_daily.sh
#   Cron:     Add to crontab to run at end of day (e.g. 23:55)
#
#   crontab -e
#   55 23 * * * /home/sek/wazuh/wazuh-monorepo/services/ai-engine/collect_daily.sh >> /home/sek/wazuh/wazuh-monorepo/services/ai-engine/data/training/collection.log 2>&1
#
# After 1-2 weeks of collection, train the model:
#   cd /home/sek/wazuh/wazuh-monorepo/services/ai-engine
#   python3 train_isolation_forest.py

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "--- Collection run: $(date) ---"

# Use the project venv if it exists, otherwise system python
if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python3"
elif [ -f "$SCRIPT_DIR/../../apps/backend/venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/../../apps/backend/venv/bin/python3"
else
    PYTHON="python3"
fi

$PYTHON collect_training_data.py

echo "--- Done: $(date) ---"
