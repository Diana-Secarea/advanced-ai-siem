#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Selenne — macOS log collector
#
#  Installs the endpoint collector on this Mac and enrols it with your Selenne
#  account. The collector only reads logs and ships them to https://__MANAGER__
#  — all detection and ML scoring happens there, nothing is analysed locally.
#  Works on both Apple Silicon and Intel Macs.
#
#  Run:   sudo bash install-selenne-collector-macos.sh
#
#  This file is generated for your account — do not share it.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MANAGER='__MANAGER__'
REG_PASSWORD='__REG_PASSWORD__'
OWNER='__OWNER__'
AGENT_GROUP='__AGENT_GROUP__'
AGENT_VERSION='__AGENT_VERSION__'

# macOS installs under /Library/Ossec, not /var/ossec
OSSEC=/Library/Ossec
MACHINE="${SELENNE_AGENT_NAME:-$(scutil --get ComputerName 2>/dev/null || hostname -s)}"
# spaces are legal in a Mac's name but not in an agent name
MACHINE="${MACHINE// /-}"
AGENT_NAME="${OWNER}__${MACHINE}"

say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

say "== Selenne collector (macOS) =="

[ "$(id -u)" -eq 0 ] || die "Run with sudo:  sudo bash $0"

# 1. Install the collector package ------------------------------------------
if [ -x "$OSSEC/bin/wazuh-control" ]; then
    say "  Collector already installed — re-enrolling it with your account."
    "$OSSEC/bin/wazuh-control" stop >/dev/null 2>&1 || true
else
    case "$(uname -m)" in
        arm64)  ARCH=arm64   ; CHIP="Apple Silicon" ;;
        x86_64) ARCH=intel64 ; CHIP="Intel" ;;
        *)      die "Unsupported CPU architecture: $(uname -m)" ;;
    esac
    PKG="wazuh-agent-${AGENT_VERSION}-1.${ARCH}.pkg"
    URL="https://packages.wazuh.com/4.x/macos/${PKG}"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT

    say "  Downloading the collector for ${CHIP} (~13 MB)..."
    curl -fsSL "$URL" -o "$TMP/$PKG" \
        || die "Could not download $URL — check this Mac's internet connection."

    say "  Installing..."
    # WAZUH_MANAGER is read by the package's postinstall script
    echo "WAZUH_MANAGER='${MANAGER}'" > /tmp/wazuh_envs
    installer -pkg "$TMP/$PKG" -target / >/dev/null \
        || die "Package installation failed."
    rm -f /tmp/wazuh_envs
fi

# 2. Point it at Selenne and enrol -------------------------------------------
say "  Enrolling as '${MACHINE}' (account: ${OWNER})..."
if [ -f "$OSSEC/etc/ossec.conf" ]; then
    /usr/bin/sed -i '' "s#<address>[^<]*</address>#<address>${MANAGER}</address>#" \
        "$OSSEC/etc/ossec.conf" 2>/dev/null || true
fi

"$OSSEC/bin/agent-auth" -m "$MANAGER" -P "$REG_PASSWORD" \
                        -A "$AGENT_NAME" -G "$AGENT_GROUP" \
    || die "Enrolment failed — check that ${MANAGER}:1515 is reachable from this Mac."

# 3. Start it ----------------------------------------------------------------
say "  Starting the collector service..."
"$OSSEC/bin/wazuh-control" start >/dev/null 2>&1 || true

sleep 5
if "$OSSEC/bin/wazuh-control" status 2>/dev/null | grep -q "is running"; then
    echo
    say "Done — this Mac is now monitored by Selenne."
    printf '  Events stream to https://%s and appear in Live Alerts within a minute.\n' "$MANAGER"
    printf '  Endpoint: %s   (account: %s)\n' "$MACHINE" "$OWNER"
    echo
    warn "macOS may ask you to grant Full Disk Access for complete log collection:"
    warn "System Settings → Privacy & Security → Full Disk Access → enable 'wazuh-agent'"
else
    warn "The collector did not start. Check: $OSSEC/logs/ossec.log"
fi
