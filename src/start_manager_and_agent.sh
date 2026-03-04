#!/bin/bash
# Start Wazuh Manager and Agent (run in terminal so you can enter sudo password)

set -e
WAZUH_SRC="/home/sek/wazuh/src"

echo "=========================================="
echo "Starting Wazuh Manager and Agent"
echo "=========================================="
echo ""

# 1. Start Manager (package at /var/ossec)
echo "1. Starting Wazuh Manager..."
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    echo "   Manager is already running."
else
    sudo systemctl start wazuh-manager
    echo "   Manager started."
fi
sleep 2

# Verify manager is listening
if ss -tuln 2>/dev/null | grep -q ":1514" || netstat -tuln 2>/dev/null | grep -q ":1514"; then
    echo "   Port 1514 is listening."
else
    echo "   Warning: Port 1514 not yet listening. Manager may still be starting."
fi
echo ""

# 2. Start Agent (compiled in src)
echo "2. Starting Wazuh Agent..."
cd "$WAZUH_SRC"
if pgrep -f "wazuh-agentd" > /dev/null; then
    echo "   Agent is already running (PID: $(pgrep -f wazuh-agentd))."
else
    ./start_agent_sudo.sh
fi
echo ""

echo "=========================================="
echo "Done. Check status: $WAZUH_SRC/check_status.sh"
echo "=========================================="
