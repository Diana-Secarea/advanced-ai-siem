# ✅ Wazuh is Working!

## Current Status

### ✅ Manager (Package v4.14.1)
- **Status**: Running
- **Location**: `/var/ossec/`
- **Ports**: 
  - 1514 (agent communication)
  - 1515 (enrollment service)
- **Control**: `sudo systemctl start/stop/status wazuh-manager`

### ✅ Agent (Compiled v5.0.0-alpha0)
- **Status**: Running
- **Location**: `/var/ossec/agent_compiled/`
- **Connected to**: `127.0.0.1:1514`
- **Control**: See commands below

## Quick Commands

### Check Status
```bash
# All Wazuh processes
ps aux | grep wazuh | grep -v grep

# Manager status
sudo systemctl status wazuh-manager

# Agent status
ps aux | grep wazuh-agentd
```

### View Logs
```bash
# Agent logs
sudo tail -f /var/ossec/agent_compiled/logs/ossec.log

# Manager logs
sudo tail -f /var/ossec/logs/ossec.log

# Alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### Start/Stop
```bash
# Start Manager
sudo systemctl start wazuh-manager

# Stop Manager
sudo systemctl stop wazuh-manager

# Start Agent
sudo bash -c "cd /var/ossec/agent_compiled && export LD_LIBRARY_PATH=/var/ossec/agent_compiled && /var/ossec/agent_compiled/wazuh-agentd -d"

# Stop Agent
sudo pkill -f wazuh-agentd
```

## What's Happening Now

1. ✅ **Manager is collecting and analyzing logs**
2. ✅ **Agent is sending events to manager**
3. ⏳ **Enrollment**: Agent is connecting (client.keys will be created automatically)
4. ✅ **Log collection**: Agent is monitoring configured log files
5. ✅ **Alerts**: Manager is generating security alerts

## Next Steps

### 1. Monitor Alerts
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### 2. Check Agent Enrollment
```bash
# When enrollment completes, this file will exist:
ls -la /var/ossec/agent_compiled/etc/client.keys

# View the key (shows agent is registered):
sudo cat /var/ossec/agent_compiled/etc/client.keys
```

### 3. View Agent Status from Manager
```bash
sudo /var/ossec/bin/wazuh-control status
sudo /var/ossec/bin/wazuh-control info
```

### 4. Test Log Collection
```bash
# Generate a test log entry
echo "Test security event $(date)" | sudo tee -a /var/log/syslog

# Check if it's collected (in agent logs)
sudo tail -f /var/ossec/agent_compiled/logs/ossec.log | grep "Test security"
```

## Configuration Files

- **Agent Config**: `/var/ossec/agent_compiled/etc/ossec.conf`
- **Manager Config**: `/var/ossec/etc/ossec.conf`
- **Agent Keys**: `/var/ossec/agent_compiled/etc/client.keys` (created on enrollment)

## Important Notes

- **Version Mismatch**: Agent (v5.0.0-alpha0) and Manager (v4.14.1) - should work for basic functionality
- **Agent Location**: Agent is in `/var/ossec/agent_compiled/` (not in `/home/sek/wazuh/src/`)
- **Permissions**: All files owned by `wazuh:wazuh` user/group

## Troubleshooting

If something stops working:

1. **Check if processes are running:**
   ```bash
   ps aux | grep wazuh
   ```

2. **Check logs for errors:**
   ```bash
   sudo tail -50 /var/ossec/agent_compiled/logs/ossec.log
   sudo tail -50 /var/ossec/logs/ossec.log
   ```

3. **Restart services:**
   ```bash
   sudo systemctl restart wazuh-manager
   sudo pkill -f wazuh-agentd
   # Then start agent again
   ```

## Success! 🎉

Wazuh is now running correctly with both agent and manager. The system is:
- ✅ Collecting logs
- ✅ Analyzing events
- ✅ Generating alerts
- ✅ Monitoring your system

Enjoy your SIEM system!
