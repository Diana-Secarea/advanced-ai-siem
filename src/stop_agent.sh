#!/bin/bash
# Stop Wazuh Agent

WAZUH_HOME="/home/sek/wazuh/src"

echo "Stopping Wazuh Agent..."

if pgrep -f "wazuh-agentd" > /dev/null; then
    AGENT_PID=$(pgrep -f "wazuh-agentd")
    echo "Found agent process (PID: $AGENT_PID)"
    
    # Try graceful shutdown first
    sudo kill -TERM $AGENT_PID 2>/dev/null
    sleep 2
    
    # Check if still running
    if pgrep -f "wazuh-agentd" > /dev/null; then
        echo "Force killing..."
        sudo kill -9 $AGENT_PID 2>/dev/null
        sleep 1
    fi
    
    if ! pgrep -f "wazuh-agentd" > /dev/null; then
        echo "✅ Agent stopped"
    else
        echo "⚠️  Agent may still be running"
    fi
else
    echo "Agent is not running"
fi
