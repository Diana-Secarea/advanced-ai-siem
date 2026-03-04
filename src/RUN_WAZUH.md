# How to Run Wazuh Correctly - Step by Step

## Current Situation

- ✅ **Agent compiled**: `/home/sek/wazuh/src/wazuh-agentd` (v5.0.0-alpha0)
- ✅ **Manager installed**: Package version (v4.14.1) at `/var/ossec`
- ⚠️ **Version mismatch**: May cause compatibility issues, but should work for basic testing

## Complete Setup Instructions

### Step 1: Fix Permissions

Run these commands with sudo:

```bash
cd /home/sek/wazuh/src

# Create directories if needed
sudo mkdir -p queue/sockets var/sockets var/run var/db var/diff

# Set ownership
sudo chown -R wazuh:wazuh queue logs var etc

# Set permissions
sudo chmod -R 750 queue logs var etc
sudo chmod 640 etc/client.keys 2>/dev/null || true
```

### Step 2: Start Manager

```bash
# Check if manager is installed
sudo systemctl status wazuh-manager

# Start manager
sudo systemctl start wazuh-manager

# Enable auto-start on boot (optional)
sudo systemctl enable wazuh-manager

# Verify it's running
sudo systemctl status wazuh-manager

# Check if port 1514 is listening
sudo netstat -tuln | grep 1514
# or
sudo ss -tuln | grep 1514
```

### Step 3: Configure Agent

The agent config is already set to connect to `127.0.0.1:1514`. Verify:

```bash
grep -A 2 "<server>" /home/sek/wazuh/src/etc/ossec.conf
```

Should show:
```xml
<server>
  <address>127.0.0.1</address>
  <port>1514</port>
</server>
```

### Step 4: Start Agent

```bash
cd /home/sek/wazuh/src
./start_agent.sh
```

If you get permission errors, run manually:

```bash
cd /home/sek/wazuh/src
export LD_LIBRARY_PATH=/home/sek/wazuh/src
sudo -u wazuh bash -c "export LD_LIBRARY_PATH=/home/sek/wazuh/src && cd /home/sek/wazuh/src && ./wazuh-agentd -d"
```

### Step 5: Check Status

```bash
cd /home/sek/wazuh/src
./check_status.sh
```

Or manually:

```bash
# Check if agent is running
ps aux | grep wazuh-agentd

# Check if manager is running
sudo systemctl status wazuh-manager

# Check agent logs
tail -f /home/sek/wazuh/src/logs/ossec.log

# Check manager logs
sudo tail -f /var/ossec/logs/ossec.log
```

### Step 6: Verify Connection

The agent should auto-enroll. Check logs:

```bash
# Agent logs - look for enrollment messages
tail -50 /home/sek/wazuh/src/logs/ossec.log | grep -i enroll

# Manager logs - look for agent connection
sudo tail -50 /var/ossec/logs/ossec.log | grep -i agent
```

If client.keys is created, connection is successful:

```bash
ls -la /home/sek/wazuh/src/etc/client.keys
cat /home/sek/wazuh/src/etc/client.keys  # Should show agent ID and key
```

## Troubleshooting

### Manager won't start

```bash
# Check manager logs
sudo tail -50 /var/ossec/logs/ossec.log

# Check systemd status
sudo systemctl status wazuh-manager

# Try restarting
sudo systemctl restart wazuh-manager
```

### Agent won't start

```bash
# Check permissions
ls -la /home/sek/wazuh/src/queue
ls -la /home/sek/wazuh/src/logs

# Fix if needed
sudo chown -R wazuh:wazuh /home/sek/wazuh/src/queue
sudo chown -R wazuh:wazuh /home/sek/wazuh/src/logs
sudo chown -R wazuh:wazuh /home/sek/wazuh/src/var

# Check agent logs
tail -50 /home/sek/wazuh/src/logs/ossec.log
```

### Agent can't connect to manager

1. **Verify manager is running:**
```bash
sudo systemctl status wazuh-manager
sudo netstat -tuln | grep 1514
```

2. **Check network connectivity:**
```bash
telnet 127.0.0.1 1514
# or
nc -zv 127.0.0.1 1514
```

3. **Check firewall:**
```bash
sudo iptables -L -n | grep 1514
# If blocked, allow it:
sudo iptables -A INPUT -p tcp --dport 1514 -j ACCEPT
```

4. **Check manager config:**
```bash
sudo grep -A 5 "<remote>" /var/ossec/etc/ossec.conf
```

Should show:
```xml
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
</remote>
```

### Version compatibility issues

If you see errors about version mismatch:

**Option A: Use compiled manager (recommended for development)**
```bash
cd /home/sek/wazuh/src
make TARGET=server
# Then use ./start_manager.sh instead of systemctl
```

**Option B: Use package agent (if available)**
```bash
sudo apt-get install wazuh-agent
sudo systemctl start wazuh-agent
```

## Quick Reference

### Start Services
```bash
# Manager
sudo systemctl start wazuh-manager

# Agent
cd /home/sek/wazuh/src && ./start_agent.sh
```

### Stop Services
```bash
# Agent
cd /home/sek/wazuh/src && ./stop_agent.sh

# Manager
sudo systemctl stop wazuh-manager
```

### Check Status
```bash
cd /home/sek/wazuh/src && ./check_status.sh
```

### View Logs
```bash
# Agent
tail -f /home/sek/wazuh/src/logs/ossec.log

# Manager
sudo tail -f /var/ossec/logs/ossec.log

# Alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

## Expected Behavior

When everything is working:

1. ✅ Manager is running and listening on port 1514
2. ✅ Agent is running and connected to manager
3. ✅ `client.keys` file exists in `/home/sek/wazuh/src/etc/`
4. ✅ Agent logs show successful connection
5. ✅ Manager logs show agent registration
6. ✅ Alerts are being generated in `/var/ossec/logs/alerts/`

## Next Steps After Setup

1. **Monitor alerts:**
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

2. **Check agent status from manager:**
```bash
sudo /var/ossec/bin/wazuh-control status
```

3. **View agent list:**
```bash
sudo /var/ossec/bin/wazuh-control info
```

4. **Test log collection:**
```bash
# Generate a test log
echo "Test log entry $(date)" | sudo tee -a /var/log/syslog

# Check if it's collected (in agent logs)
tail -f /home/sek/wazuh/src/logs/ossec.log | grep "Test log"
```

## Files Created

- `setup_wazuh.sh` - Main setup script
- `setup_authentication.sh` - Authentication helper
- `start_agent.sh` - Start agent script
- `stop_agent.sh` - Stop agent script
- `check_status.sh` - Status checker
- `QUICK_START.md` - Quick reference guide
- `RUN_WAZUH.md` - This file

All scripts are executable and ready to use!
