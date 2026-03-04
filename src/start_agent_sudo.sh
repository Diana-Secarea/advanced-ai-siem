#!/bin/bash
# Start Wazuh Agent with sudo (runs as root then drops to wazuh).
# One-time: sudo ./setup_agent_for_user.sh --sudo-agent
# Then:     ./start_agent_sudo.sh

WAZUH_HOME="/home/sek/wazuh/src"
cd "$WAZUH_HOME" || exit 1

if pgrep -f "wazuh-agentd" > /dev/null; then
    echo "Agent already running. Stop first: $WAZUH_HOME/stop_agent.sh"
    exit 1
fi

echo "Starting Wazuh Agent (with sudo)..."
# WAZUH_HOME is needed so the agent finds etc/ossec.conf when run under sudo (logging reads it early)
sudo bash -c "cd '$WAZUH_HOME' && export WAZUH_HOME='$WAZUH_HOME' && export LD_LIBRARY_PATH='$WAZUH_HOME' && exec '$WAZUH_HOME/wazuh-agentd' -d"
sleep 4
if pgrep -f "wazuh-agentd" > /dev/null || pgrep -f "wazuh-logcollector" > /dev/null; then
    echo "✅ Agent started. Logs: tail -f $WAZUH_HOME/logs/ossec.log"
else
    echo "❌ Start failed. Try:"
    echo "   1. sudo ./setup_agent_for_user.sh --sudo-agent   (fix ownership + remove stale sockets)"
    echo "   2. ./start_agent_sudo.sh"
    echo "   Logs: tail -20 $WAZUH_HOME/logs/ossec.log"
    exit 1
fi
