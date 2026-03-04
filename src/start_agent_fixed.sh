#!/bin/bash
# Start Wazuh Agent (Fixed version - runs from /var/ossec/agent_compiled)

AGENT_HOME="/var/ossec/agent_compiled"

# Check if agent directory exists
if [ ! -d "$AGENT_HOME" ]; then
    echo "❌ Agent not found at $AGENT_HOME"
    echo "   Run setup first or copy agent files manually"
    exit 1
fi

# Check if already running
if pgrep -f "wazuh-agentd" > /dev/null; then
    echo "⚠️  Agent is already running (PID: $(pgrep -f wazuh-agentd))"
    echo "   Stop it first: sudo pkill -f wazuh-agentd"
    exit 1
fi

echo "Starting Wazuh Agent from $AGENT_HOME..."
echo "Manager should be at: 127.0.0.1:1514"
echo ""

# Start agent as wazuh user
sudo -u wazuh bash -c "cd $AGENT_HOME && export LD_LIBRARY_PATH=$AGENT_HOME && $AGENT_HOME/wazuh-agentd -d"

sleep 2

# Check if started successfully
if pgrep -f "wazuh-agentd" > /dev/null; then
    echo "✅ Agent started successfully (PID: $(pgrep -f wazuh-agentd))"
    echo ""
    echo "Check logs:"
    echo "  tail -f $AGENT_HOME/logs/ossec.log"
    echo ""
    echo "Check status:"
    echo "  ps aux | grep wazuh-agentd"
else
    echo "❌ Agent failed to start. Check logs:"
    echo "  tail -20 $AGENT_HOME/logs/ossec.log"
    exit 1
fi
