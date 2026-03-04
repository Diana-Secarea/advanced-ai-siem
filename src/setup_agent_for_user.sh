#!/bin/bash
# One-time setup: fix agent dir ownership.
# Run once:  sudo ./setup_agent_for_user.sh
#
# By default: gives ownership to YOU so ./start_agent.sh (no sudo) works.
# With --sudo-agent: gives ownership to wazuh so "sudo ./wazuh-agentd -d" works.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
USE_SUDO_AGENT=false
WAZUH_HOME="$SCRIPT_DIR"
for a in "$@"; do
    if [[ "$a" == "--sudo-agent" ]]; then
        USE_SUDO_AGENT=true
    elif [[ -d "$a/etc" ]]; then
        WAZUH_HOME="$a"
    fi
done

if [[ ! -d "$WAZUH_HOME/etc" ]]; then
    echo "Usage: sudo $0 [WAZUH_SRC_DIR] [--sudo-agent]"
    echo "  Default: ownership to you → run with: ./start_agent.sh (no sudo)"
    echo "  --sudo-agent: ownership to wazuh → run with: sudo ./wazuh-agentd -d"
    exit 1
fi

# Must run as root (for chown)
if [[ "$(id -u)" != "0" ]]; then
    echo "Run with sudo so permissions can be fixed:"
    echo "  sudo $0 $WAZUH_HOME"
    exit 1
fi

if [[ "$USE_SUDO_AGENT" == true ]]; then
    TARGET_USER="wazuh"
    echo "Setting ownership to wazuh (for running agent with sudo)..."
else
    TARGET_USER="${SUDO_USER:-$(stat -c '%U' "$WAZUH_HOME" 2>/dev/null)}"
    if [[ -z "$TARGET_USER" ]]; then
        TARGET_USER="$(logname 2>/dev/null)" || true
    fi
    if [[ -z "$TARGET_USER" ]]; then
        echo "Could not determine user. Run as: sudo -u YOUR_USER $0"
        exit 1
    fi
    echo "Setting ownership of agent dirs to $TARGET_USER (run with ./start_agent.sh, no sudo)..."
fi

for dir in etc queue logs var; do
    if [[ -d "$WAZUH_HOME/$dir" ]]; then
        chown -R "$TARGET_USER:$TARGET_USER" "$WAZUH_HOME/$dir"
        echo "  chown $TARGET_USER $WAZUH_HOME/$dir"
    fi
done
# When using sudo: root must read etc/ossec.conf before dropping to wazuh
if [[ "$USE_SUDO_AGENT" == true ]]; then
    chmod -R o+rX "$WAZUH_HOME/etc"
    [[ -f "$WAZUH_HOME/etc/ossec.conf" ]] && chmod o+r "$WAZUH_HOME/etc/ossec.conf"
    echo "  chmod o+rX etc (so root can read config when starting with sudo)"
fi
# Ensure queue/sockets exists; remove stale socket so agent can create it with correct owner
mkdir -p "$WAZUH_HOME/queue/sockets"
rm -f "$WAZUH_HOME/queue/sockets/queue"
chown -R "$TARGET_USER:$TARGET_USER" "$WAZUH_HOME/queue"
chmod -R u+rwX,g+rwX "$WAZUH_HOME/queue"

# Add explicit logging to ossec.conf so logs go to logs/ossec.log (optional but recommended)
OSSEC_CONF="$WAZUH_HOME/etc/ossec.conf"
if [[ -f "$OSSEC_CONF" ]] && ! grep -q "<log_format>" "$OSSEC_CONF" 2>/dev/null; then
    echo "Adding <logging><log_format>plain</log_format></logging> to etc/ossec.conf"
    if command -v python3 &>/dev/null; then
        python3 - "$OSSEC_CONF" << 'PY'
import sys
path = sys.argv[1]
p = open(path).read()
if "<log_format>" in p:
    sys.exit(0)
p = p.replace("<ossec_config>", "<ossec_config>\n  <logging>\n    <log_format>plain</log_format>\n  </logging>", 1)
open(path, "w").write(p)
PY
    else
        # Fallback: sed (GNU)
        sed -i '/^<ossec_config>$/a\  <logging>\n    <log_format>plain</log_format>\n  </logging>' "$OSSEC_CONF" 2>/dev/null || true
    fi
fi

echo ""
echo "Done. You can now:"
echo "  - Start the agent:  ./start_agent.sh"
echo "  - Edit config:      $WAZUH_HOME/etc/ossec.conf"
echo "  - View logs:        tail -f $WAZUH_HOME/logs/ossec.log"
echo ""
