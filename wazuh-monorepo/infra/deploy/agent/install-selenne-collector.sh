#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Selenne — Linux log collector
#
#  Installs the endpoint collector on this machine and enrols it with your
#  Selenne account. The collector only reads logs and ships them to
#  https://__DASHBOARD__ — all detection and ML scoring happens there, nothing
#  is analysed locally. ~13 MB download, runs as a background service.
#
#  Run:   sudo bash install-selenne-collector.sh
#
#  This file is generated for your account — do not share it.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Two hosts on purpose: agent traffic is raw TCP on 1514/1515, so MANAGER must
# be a DNS-only name pointing at the origin. DASHBOARD is the https name to open.
MANAGER='__MANAGER__'
DASHBOARD='__DASHBOARD__'
REG_PASSWORD='__REG_PASSWORD__'
OWNER='__OWNER__'
AGENT_GROUP='__AGENT_GROUP__'
# The owner travels with the agent name so events are attributed to the right
# account even after a re-enrolment.
MACHINE="${SELENNE_AGENT_NAME:-$(hostname -s)}"
AGENT_NAME="${OWNER}__${MACHINE}"

say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

say "== Selenne collector =="

[ "$(id -u)" -eq 0 ] || die "Run with sudo:  sudo bash $0"

# 1. Install the collector package ------------------------------------------
if [ -x /var/ossec/bin/wazuh-control ]; then
    say "  Collector already installed — re-enrolling it with your account."
    systemctl stop wazuh-agent 2>/dev/null || true
else
    say "  Installing the collector (~13 MB)..."
    if command -v apt-get >/dev/null 2>&1; then
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import >/dev/null 2>&1
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q >/dev/null
        apt-get install -yq wazuh-agent >/dev/null
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
        if command -v dnf >/dev/null 2>&1; then dnf install -y wazuh-agent >/dev/null
        else yum install -y wazuh-agent >/dev/null; fi
    elif command -v zypper >/dev/null 2>&1; then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        zypper -n ar -f https://packages.wazuh.com/4.x/yum/ wazuh >/dev/null 2>&1 || true
        zypper -n install wazuh-agent >/dev/null
    else
        die "Unsupported distribution — no apt, dnf, yum or zypper found."
    fi
fi

# 2. Point it at Selenne and enrol -------------------------------------------
say "  Enrolling as '${MACHINE}' (account: ${OWNER})..."
sed -i "s#<address>[^<]*</address>#<address>${MANAGER}</address>#" /var/ossec/etc/ossec.conf

/var/ossec/bin/agent-auth -m "$MANAGER" -P "$REG_PASSWORD" \
                          -A "$AGENT_NAME" -G "$AGENT_GROUP" \
    || die "Enrolment failed — check that ${MANAGER}:1515 is reachable from this machine."

# 3. Start it ----------------------------------------------------------------
say "  Starting the collector service..."
systemctl daemon-reload 2>/dev/null || true
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent

sleep 5
if systemctl is-active --quiet wazuh-agent; then
    echo
    say "Done — this machine is now monitored by Selenne."
    printf '  Events stream to https://%s and appear in Live Alerts within a minute.\n' "$DASHBOARD"
    printf '  Endpoint: %s   (account: %s)\n' "$MACHINE" "$OWNER"
else
    warn "The service did not start. Check: journalctl -u wazuh-agent -n 30"
    warn "or /var/ossec/logs/ossec.log"
fi
