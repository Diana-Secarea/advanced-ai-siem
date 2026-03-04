#!/bin/bash
# Start Wazuh Agent (same as the working command: run from src with LD_LIBRARY_PATH)

WAZUH_HOME="/home/sek/wazuh/src"
export LD_LIBRARY_PATH="$WAZUH_HOME:$LD_LIBRARY_PATH"

cd "$WAZUH_HOME" || exit 1

# One-time setup: run once so agent and config work every time
if [[ "${1:-}" == "fix_permissions" ]] || [[ "${1:-}" == "fix_config_permissions" ]]; then
    echo "Run this once (with sudo) so the agent and etc/ossec.conf work every time:"
    echo ""
    echo "  sudo $WAZUH_HOME/setup_agent_for_user.sh"
    echo ""
    echo "That script will: give you ownership of etc, queue, logs, var; add logging to ossec.conf."
    exit 0
fi

# Agent needs to read etc/ossec.conf
if [[ ! -r "$WAZUH_HOME/etc/ossec.conf" ]]; then
    echo "❌ Cannot read $WAZUH_HOME/etc/ossec.conf (permission denied)."
    echo "   Fix once: sudo $WAZUH_HOME/setup_agent_for_user.sh"
    exit 1
fi

# Check if already running
if pgrep -f "wazuh-agentd" > /dev/null; then
    echo "⚠️  Agent is already running (PID: $(pgrep -f wazuh-agentd))"
    echo "   Stop it first: $WAZUH_HOME/stop_agent.sh"
    exit 1
fi

echo "Starting Wazuh Agent..."
echo "Manager should be at: 127.0.0.1:1514"
echo ""

# Run as current user: -u/-g avoid "Unable to switch to group 'wazuh'" when not root
"$WAZUH_HOME/wazuh-agentd" -d -u "$(whoami)" -g "$(id -gn)"

# Daemon may fork; give it time and check for any agent process
sleep 3
if pgrep -f "wazuh-agentd" > /dev/null || pgrep -f "wazuh-logcollector" > /dev/null || pgrep -f "wazuh-modulesd" > /dev/null; then
    echo "✅ Agent started successfully"
    echo ""
    echo "--- Where to see logs ---"
    echo "  Agent (this machine):  tail -f $WAZUH_HOME/logs/ossec.log"
    echo "  Manager (if running): sudo tail -f /var/ossec/logs/ossec.log"
    echo "  Manager alerts:        sudo tail -f /var/ossec/logs/alerts/alerts.log"
    echo ""
    if ! (command -v ss &>/dev/null && ss -tuln 2>/dev/null | grep -q ":1514 ") && ! (command -v netstat &>/dev/null && netstat -tuln 2>/dev/null | grep -q ":1514 "); then
        echo "  ⚠️  Manager not listening on 1514. Start it for agent→manager logs:"
        echo "      sudo systemctl start wazuh-manager"
        echo ""
    fi
    echo "  Connection status:    ./check_status.sh"
    echo "  (Agent must connect to manager for alerts to appear in manager logs.)"
    echo ""
else
    echo "❌ Agent exited (often: cannot write to queue/logs/var)."
    echo "   Fix once: sudo $WAZUH_HOME/setup_agent_for_user.sh"
    echo ""
    echo "Then check logs: tail -20 $WAZUH_HOME/logs/ossec.log"
    exit 1
fi
