#!/usr/bin/env bash
# Lock the origin down once the manager hostname stops hiding behind Cloudflare.
#
# WHY THIS EXISTS
# Wazuh agents talk raw TCP on 1514/1515. Cloudflare's proxy answers 80/443
# only, so the agent-facing name MUST be a DNS-only (grey-cloud) record — which
# publishes the origin IP. That is an acceptable trade ONLY if the thing
# Cloudflare was protecting (the web app) stops being reachable by IP:
#
#   80/443  -> Cloudflare ranges only   (no WAF/rate-limit bypass)
#   1514/5  -> anywhere                 (agents need it, no proxy can carry it)
#   55000   -> nobody                   (Wazuh manager API; it is currently
#                                        listening on 0.0.0.0 and has no
#                                        business being public)
#   22      -> left exactly as it is    (see the SSH note below)
#
# Companion to cloudflare-realip.sh: that one restores the visitor IP for the
# rate limiter, this one stops anyone skipping the proxy entirely.
#
#   sudo ./cloudflare-firewall.sh            # DRY RUN — prints, changes nothing
#   sudo ./cloudflare-firewall.sh --apply    # actually writes the rules
#
# SSH: this script never touches port 22, and refuses to run unless a rule
# already allows it, because enabling a default-deny firewall over SSH without
# that rule locks you out of the box with no recovery short of the Hetzner
# console.
set -euo pipefail

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

command -v ufw >/dev/null || { echo "ufw not installed"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }

run() {
  if (( APPLY )); then
    echo "  + $*"; "$@"
  else
    echo "  would run: $*"
  fi
}

echo "Fetching Cloudflare ranges..."
V4="$(mktemp)"; V6="$(mktemp)"
trap 'rm -f "$V4" "$V6"' EXIT
curl -fsS https://www.cloudflare.com/ips-v4 -o "$V4"
curl -fsS https://www.cloudflare.com/ips-v6 -o "$V6"
# Cloudflare's lists have no trailing newline — read them defensively.
mapfile -t CF < <(cat "$V4" <(echo) "$V6" | sed '/^[[:space:]]*$/d')
(( ${#CF[@]} > 0 )) || { echo "no ranges fetched — refusing to continue"; exit 1; }
echo "  ${#CF[@]} ranges"

# --- SSH guard --------------------------------------------------------------
# A default-deny policy with no SSH rule ends the session that is running this.
if ! ufw status | grep -qE '(^|[[:space:]])22(/tcp)?([[:space:]]|$)'; then
  echo
  echo "REFUSING: no ufw rule for port 22 was found."
  echo "Add one first, from a session you can afford to lose:"
  echo "    sudo ufw allow 22/tcp                  # or, better, from your IP only:"
  echo "    sudo ufw allow from <your-ip> to any port 22 proto tcp"
  exit 1
fi
echo "SSH rule present — safe to continue."

echo
echo "Web ports: Cloudflare only"
run ufw --force delete allow 80/tcp  2>/dev/null || true
run ufw --force delete allow 443/tcp 2>/dev/null || true
for cidr in "${CF[@]}"; do
  run ufw allow from "$cidr" to any port 80,443 proto tcp
done

echo
echo "Agent transport: open (raw TCP, cannot be proxied)"
run ufw allow 1514/tcp
run ufw allow 1515/tcp

echo
echo "Wazuh manager API: closed to the internet"
run ufw --force delete allow 55000/tcp 2>/dev/null || true
run ufw deny 55000/tcp

echo
echo "Default policy"
run ufw default deny incoming
run ufw default allow outgoing

if (( APPLY )); then
  ufw --force enable
  echo
  ufw status verbose
  echo
  echo "Now verify from OUTSIDE the box:"
  echo "  curl -I --connect-timeout 5 http://<origin-ip>/     # should HANG or refuse"
  echo "  curl -I https://selenne.app/                        # should still work"
  echo "  nc -vz <manager-host> 1515                          # should connect"
else
  echo
  echo "DRY RUN — nothing changed. Re-run with --apply when the output looks right."
fi
