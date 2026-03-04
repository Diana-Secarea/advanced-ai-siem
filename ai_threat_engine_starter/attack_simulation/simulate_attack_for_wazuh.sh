#!/bin/bash
# Simulate MITRE ATT&CK techniques to generate Wazuh alerts.
# Run on the host where Wazuh agent is installed (e.g. Kali).
# Usage: ./simulate_attack_for_wazuh.sh [target_ip]
# Default target: 127.0.0.1

set -e
TARGET="${1:-127.0.0.1}"
TMP="/tmp/.sim_$(date +%s)"

echo "=============================================="
echo "  MITRE ATT&CK simulation for Wazuh"
echo "  Target: $TARGET"
echo "=============================================="
echo ""

# ---- CREDENTIAL ACCESS ----

# T1110 - Brute Force (SSH + password guessing)
echo "[T1110] Brute Force - SSH password guessing..."
for user in root admin administrator ubuntu ec2-user oracle postgres sshd; do
  for i in 1 2 3; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes "$user@$TARGET" 2>/dev/null || true
  done
done

# T1110 - Brute Force (sudo)
echo "[T1110] Brute Force - Repeated failed sudo..."
for i in $(seq 1 10); do
  echo "wrongpass$i" | sudo -S id 2>/dev/null || true
done

# T1003 - OS Credential Dumping (attempt to read credential stores)
echo "[T1003] OS Credential Dumping - Reading passwd/shadow locations..."
cat /etc/passwd 2>/dev/null | head -5
cat /etc/shadow 2>/dev/null | head -1 || true
grep -r "password\|passwd\|pwd" /etc/passwd 2>/dev/null | head -1 || true

# T1552 - Unsecured Credentials (search for credentials in files)
echo "[T1552] Unsecured Credentials - Searching for credential files..."
find /home /root 2>/dev/null -name "*.env" -o -name ".bash_history" -o -name "id_rsa" -o -name ".netrc" 2>/dev/null | head -10
ls -la ~/.ssh 2>/dev/null || true

# ---- DISCOVERY ----

# T1046 - Network Service Discovery (port scan)
echo "[T1046] Network Service Discovery - Port scan..."
if command -v nmap &>/dev/null; then
  nmap -sT -Pn --open -T4 "$TARGET" 2>/dev/null || true
else
  for port in 21 22 23 25 80 110 143 443 445 993 3306 3389 5432 5900 8080 8443; do
    (echo >/dev/tcp/"$TARGET"/$port) 2>/dev/null && echo "  open: $port" || true
  done
fi

# T1087 - Account Discovery
echo "[T1087] Account Discovery - Enumerating accounts..."
cat /etc/passwd | cut -d: -f1
getent group 2>/dev/null | head -15 || cat /etc/group | head -15

# T1082 - System Information Discovery
echo "[T1082] System Information Discovery..."
uname -a
hostname
cat /etc/os-release 2>/dev/null | head -10
uptime

# T1083 - File and Directory Discovery
echo "[T1083] File and Directory Discovery..."
ls -la /etc 2>/dev/null | head -20
ls -la /tmp 2>/dev/null | head -10
ls -la /etc/cron.d /etc/cron.daily 2>/dev/null || true

# T1057 - Process Discovery
echo "[T1057] Process Discovery..."
ps aux 2>/dev/null | head -25
ps -ef 2>/dev/null | head -15

# T1033 - System Owner/User Discovery
echo "[T1033] System Owner/User Discovery..."
whoami
id
w 2>/dev/null || who
last -n 5 2>/dev/null || true

# T1016 - System Network Configuration Discovery
echo "[T1016] System Network Configuration Discovery..."
ip addr 2>/dev/null || ifconfig 2>/dev/null
cat /etc/hosts 2>/dev/null
ip route 2>/dev/null || route -n 2>/dev/null

# T1049 - System Network Connections Discovery
echo "[T1049] System Network Connections Discovery..."
ss -tulpn 2>/dev/null | head -20 || netstat -tulpn 2>/dev/null | head -20

# T1007 - System Service Discovery
echo "[T1007] System Service Discovery..."
systemctl list-units --type=service 2>/dev/null | head -25 || ls /etc/init.d 2>/dev/null | head -20
ls -la /etc/systemd/system/*.service 2>/dev/null | head -10

# T1069 - Permission Groups Discovery
echo "[T1069] Permission Groups Discovery..."
groups
cat /etc/group
sudo -l -n 2>/dev/null || true

# T1201 - Password Policy Discovery
echo "[T1201] Password Policy Discovery..."
grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|UMASK" /etc/login.defs 2>/dev/null || true
cat /etc/pam.d/common-password 2>/dev/null | head -5 || true

# T1654 - Log Enumeration
echo "[T1654] Log Enumeration..."
ls -la /var/log 2>/dev/null | head -20
tail -5 /var/log/syslog 2>/dev/null || tail -5 /var/log/messages 2>/dev/null || true

# ---- DEFENSE EVASION ----

# T1070 - Indicator Removal (clear history, tamper with logs)
echo "[T1070] Indicator Removal - Clearing history..."
history -c 2>/dev/null || true
# Simulate: touch a path often cleared by attackers (we only read or create in /tmp)
touch "$TMP.log" 2>/dev/null; echo "test" >> "$TMP.log"; :> "$TMP.log"

# T1140 - Deobfuscate/Decode Files or Information
echo "[T1140] Deobfuscate/Decode - Base64 decode and execute..."
echo "d2hvYW1p" | base64 -d 2>/dev/null | bash 2>/dev/null || true
echo "ZWNobyBkZWNvZGVk" | base64 -d 2>/dev/null | bash 2>/dev/null || true

# T1027 - Obfuscated Files or Information (script embedded in command)
echo "[T1027] Obfuscated - Obfuscated command execution..."
eval 'echo "obfuscated"' 2>/dev/null
bash -c 'id' 2>/dev/null
python3 -c "import os; print(os.getcwd())" 2>/dev/null || true

# T1222 - File and Directory Permissions Modification
echo "[T1222] File and Directory Permissions Modification..."
touch "$TMP.perm" 2>/dev/null
chmod 777 "$TMP.perm" 2>/dev/null || true
chmod 644 "$TMP.perm" 2>/dev/null || true
rm -f "$TMP.perm" 2>/dev/null

# T1562 - Impair Defenses (attempt to discover/disable defenses)
echo "[T1562] Impair Defenses - Checking firewall/selinux..."
iptables -L -n 2>/dev/null | head -15 || true
getenforce 2>/dev/null || true
systemctl status wazuh-agent 2>/dev/null | head -5 || true
systemctl status fail2ban 2>/dev/null | head -3 || true

# ---- PERSISTENCE (simulated / read-only) ----

# T1136 - Create Account (attempt; will fail without root)
echo "[T1136] Create Account - useradd attempt..."
useradd -M -s /bin/false wazuh_sim_test_user 2>/dev/null || true
userdel wazuh_sim_test_user 2>/dev/null || true

# T1053 - Scheduled Task/Job (crontab discovery; no actual modification)
echo "[T1053] Scheduled Task/Job - Crontab discovery..."
crontab -l 2>/dev/null || true
# Simulate inject attempt (write to temp file only; do not install)
echo "* * * * * /bin/true" > "$TMP.cron" 2>/dev/null
cat "$TMP.cron" 2>/dev/null; rm -f "$TMP.cron" 2>/dev/null
ls -la /etc/cron.* 2>/dev/null | head -10

# T1547 - Boot or Logon Autostart (discover autostart locations)
echo "[T1547] Boot or Logon Autostart - Autostart discovery..."
cat ~/.bashrc 2>/dev/null | head -5
ls -la ~/.config/autostart /etc/xdg/autostart 2>/dev/null || true
ls -la /etc/rc.local /etc/init.d 2>/dev/null | head -5

# T1098 - Account Manipulation (SSH authorized_keys inspection)
echo "[T1098] Account Manipulation - SSH authorized_keys..."
cat ~/.ssh/authorized_keys 2>/dev/null || true
find /home /root -name "authorized_keys" 2>/dev/null -exec cat {} \; 2>/dev/null | head -5

# ---- PRIVILEGE ESCALATION ----

# T1548 - Abuse Elevation Control Mechanism
echo "[T1548] Abuse Elevation Control - sudo -l and repeated sudo..."
sudo -l 2>/dev/null || true
echo "badpass" | sudo -S -v 2>/dev/null || true

# ---- EXECUTION ----

# T1059 - Command and Scripting Interpreter (suspicious invocations)
echo "[T1059] Command and Scripting Interpreter - Script execution..."
bash -c "echo script" 2>/dev/null
sh -c "id" 2>/dev/null
perl -e "print 'perl'" 2>/dev/null || true

# ---- CLEANUP ----
rm -f "$TMP.log" "$TMP.perm" 2>/dev/null

echo ""
echo "=============================================="
echo "  MITRE ATT&CK simulation complete"
echo "=============================================="
echo "Check Wazuh for alerts mapping to:"
echo "  T1110 Brute Force"
echo "  T1003 OS Credential Dumping"
echo "  T1552 Unsecured Credentials"
echo "  T1046 Network Service Discovery"
echo "  T1087, T1082, T1083, T1057, T1033 Discovery"
echo "  T1016, T1049, T1007, T1069, T1201, T1654"
echo "  T1070 Indicator Removal"
echo "  T1140, T1027 Deobfuscate/Obfuscated"
echo "  T1222 Permissions Modification"
echo "  T1562 Impair Defenses"
echo "  T1136, T1053, T1547, T1098 Persistence"
echo "  T1548 Abuse Elevation Control"
echo "  T1059 Command and Scripting Interpreter"
