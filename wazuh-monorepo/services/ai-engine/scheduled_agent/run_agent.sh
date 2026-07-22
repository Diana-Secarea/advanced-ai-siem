#!/usr/bin/env bash
# Cron wrapper for the scheduled CVE ingestion agent.
#
# Install (run daily at 02:00):
#   crontab -e
#   0 2 * * * /home/sek/wazuh/wazuh-monorepo/services/ai-engine/scheduled_agent/run_agent.sh >> /home/sek/wazuh/wazuh-monorepo/services/ai-engine/scheduled_agent/agent.log 2>&1
#
# Requires the Postgres + Qdrant containers and Ollama to be running.

set -euo pipefail

STARTER_DIR="/home/sek/wazuh/wazuh-monorepo/services/ai-engine"
VENV_PY="${STARTER_DIR}/venv/bin/python3"

cd "${STARTER_DIR}"

echo "===== CVE ingestion run: $(date -Is) ====="
"${VENV_PY}" -m scheduled_agent.agent --source all
echo "===== done: $(date -Is) ====="
