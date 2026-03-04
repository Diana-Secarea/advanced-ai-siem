#!/bin/bash
#
# Check Wazuh Agent and Manager Status
#

WAZUH_HOME="/home/sek/wazuh/src"
PACKAGE_MANAGER_HOME="/var/ossec"

echo "=========================================="
echo "Wazuh Status Check"
echo "=========================================="
echo ""

# Check Agent
echo "📡 Agent Status:"
if pgrep -f "wazuh-agentd" > /dev/null; then
    AGENT_PID=$(pgrep -f "wazuh-agentd")
    echo "  ✅ Running (PID: $AGENT_PID)"
    
    # Check connection
    if [ -f "$WAZUH_HOME/etc/client.keys" ] && [ -s "$WAZUH_HOME/etc/client.keys" ]; then
        echo "  ✅ Authenticated (client.keys exists)"
    else
        echo "  ⚠️  Not authenticated (client.keys missing or empty)"
    fi
    
    # Check last log
    if [ -f "$WAZUH_HOME/logs/ossec.log" ]; then
        LAST_LOG=$(tail -1 "$WAZUH_HOME/logs/ossec.log" 2>/dev/null | head -c 100)
        echo "  Last log: $LAST_LOG..."
    fi
else
    echo "  ❌ Not running"
fi

echo ""

# Check Manager (Package)
echo "🖥️  Manager Status (Package):"
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    echo "  ✅ Running (systemd service)"
    # Avoid sudo in non-interactive use; user can run: sudo systemctl status wazuh-manager
    if systemctl show wazuh-manager -p ActiveState -p SubState --value 2>/dev/null | grep -q running; then
        echo "  State: $(systemctl show wazuh-manager -p SubState --value 2>/dev/null)"
    fi
elif pgrep -f "wazuh-managerd\|ossec-remoted" > /dev/null; then
    MANAGER_PID=$(pgrep -f "wazuh-managerd\|ossec-remoted")
    echo "  ✅ Running (PID: $MANAGER_PID)"
else
    echo "  ❌ Not running"
    echo "  Start with: sudo systemctl start wazuh-manager"
fi

echo ""

# Check Manager (Compiled)
if [ -f "$WAZUH_HOME/wazuh-managerd" ]; then
    echo "🖥️  Manager Status (Compiled):"
    if pgrep -f "$WAZUH_HOME/wazuh-managerd" > /dev/null; then
        MANAGER_PID=$(pgrep -f "$WAZUH_HOME/wazuh-managerd")
        echo "  ✅ Running (PID: $MANAGER_PID)"
    else
        echo "  ❌ Not running"
        echo "  Start with: $WAZUH_HOME/start_manager.sh"
    fi
    echo ""
fi

# Check connectivity
echo "🔌 Connectivity:"
if command -v netstat &> /dev/null; then
    if netstat -tuln 2>/dev/null | grep -q ":1514"; then
        echo "  ✅ Port 1514 is listening (manager ready)"
    else
        echo "  ⚠️  Port 1514 not listening (manager may not be ready)"
    fi
elif command -v ss &> /dev/null; then
    if ss -tuln 2>/dev/null | grep -q ":1514"; then
        echo "  ✅ Port 1514 is listening (manager ready)"
    else
        echo "  ⚠️  Port 1514 not listening (manager may not be ready)"
    fi
fi

echo ""

# Check logs location
echo "📋 Log Locations:"
echo "  Agent logs:  $WAZUH_HOME/logs/ossec.log"
if [ -d "$PACKAGE_MANAGER_HOME/logs" ]; then
    echo "  Manager logs: $PACKAGE_MANAGER_HOME/logs/ossec.log"
fi
echo ""

# Quick commands
echo "💡 Quick Commands:"
echo "  View agent logs:    tail -f $WAZUH_HOME/logs/ossec.log"
if [ -d "$PACKAGE_MANAGER_HOME" ]; then
    echo "  View manager logs:  sudo tail -f $PACKAGE_MANAGER_HOME/logs/ossec.log"
fi
echo "  Restart agent:      $WAZUH_HOME/stop_agent.sh && $WAZUH_HOME/start_agent.sh"
echo "  Restart manager:    sudo systemctl restart wazuh-manager"
echo ""
