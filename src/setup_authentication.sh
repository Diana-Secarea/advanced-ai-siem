#!/bin/bash
#
# Wazuh Authentication Setup
# Sets up agent-manager authentication
#

set -e

WAZUH_HOME="/home/sek/wazuh/src"
PACKAGE_MANAGER_HOME="/var/ossec"

echo "=========================================="
echo "Wazuh Authentication Setup"
echo "=========================================="
echo ""

# Check if manager is running (package)
if systemctl is-active --quiet wazuh-manager 2>/dev/null || pgrep -f "wazuh-managerd\|ossec-remoted" > /dev/null; then
    echo "✅ Manager is running"
    MANAGER_RUNNING=true
else
    echo "⚠️  Manager is not running. Starting it..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl start wazuh-manager || echo "⚠️  Could not start manager"
    fi
    MANAGER_RUNNING=false
fi

# Method 1: Use agent-auth to enroll
echo ""
echo "Method 1: Auto-enrollment (Recommended)"
echo "----------------------------------------"
echo "The agent will automatically enroll when it starts."
echo "Make sure manager is running and accessible."
echo ""

# Method 2: Manual enrollment
echo "Method 2: Manual enrollment"
echo "----------------------------------------"
echo "If auto-enrollment fails, use agent-auth:"
echo ""
echo "1. Get manager IP:"
if [ -f "$PACKAGE_MANAGER_HOME/etc/ossec.conf" ]; then
    MANAGER_IP=$(grep -A 1 "<remote>" "$PACKAGE_MANAGER_HOME/etc/ossec.conf" | grep -oP '(?<=<address>)[^<]+' | head -1 || echo "127.0.0.1")
    echo "   Manager IP: $MANAGER_IP"
else
    echo "   Manager IP: 127.0.0.1 (default)"
    MANAGER_IP="127.0.0.1"
fi

echo ""
echo "2. Run agent-auth (if available):"
if [ -f "$WAZUH_HOME/agent-auth" ]; then
    echo "   $WAZUH_HOME/agent-auth -m $MANAGER_IP"
elif [ -f "$PACKAGE_MANAGER_HOME/bin/agent-auth" ]; then
    echo "   $PACKAGE_MANAGER_HOME/bin/agent-auth -m $MANAGER_IP"
else
    echo "   agent-auth not found. Auto-enrollment will be used."
fi

echo ""
echo "3. Or manually add key to client.keys:"
echo "   Format: <agent_id> <agent_name> <agent_ip> <key>"
echo "   Get key from manager: /var/ossec/etc/client.keys (agent entry)"

# Check current client.keys
echo ""
echo "Current client.keys status:"
if [ -f "$WAZUH_HOME/etc/client.keys" ]; then
    KEY_COUNT=$(wc -l < "$WAZUH_HOME/etc/client.keys" 2>/dev/null || echo "0")
    if [ "$KEY_COUNT" -gt 0 ]; then
        echo "✅ client.keys exists with $KEY_COUNT entry/entries"
        echo "   (Content hidden for security)"
    else
        echo "⚠️  client.keys exists but is empty"
    fi
else
    echo "⚠️  client.keys does not exist"
    echo "   Will be created on first successful enrollment"
fi

echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo "1. Ensure manager is running:"
echo "   sudo systemctl status wazuh-manager"
echo ""
echo "2. Start the agent:"
echo "   $WAZUH_HOME/start_agent.sh"
echo ""
echo "3. Check agent logs:"
echo "   tail -f $WAZUH_HOME/logs/ossec.log"
echo ""
echo "4. Check manager logs:"
echo "   sudo tail -f /var/ossec/logs/ossec.log"
echo ""
echo "5. Verify connection:"
echo "   sudo /var/ossec/bin/wazuh-control status"
echo ""
