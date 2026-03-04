# Wazuh Setup - Final Status

## ✅ Completed Setup

### 1. Permissions Fixed
- ✅ All directories have correct ownership (wazuh:wazuh)
- ✅ Permissions set to 750

### 2. Manager Running
- ✅ Wazuh Manager (package v4.14.1) is running
- ✅ Listening on port 1514 (agent communication)
- ✅ Listening on port 1515 (enrollment service)
- ✅ Status: `sudo systemctl status wazuh-manager`

### 3. Agent Setup
- ✅ Agent binary copied to `/var/ossec/agent_compiled`
- ✅ Agent configuration ready
- ✅ Queue directories created

## Current Status

### Manager
```bash
sudo systemctl status wazuh-manager
# Should show: active (running)
```

### Agent
The agent is located at: `/var/ossec/agent_compiled`

To start the agent:
```bash
sudo bash -c "cd /var/ossec/agent_compiled && export LD_LIBRARY_PATH=/var/ossec/agent_compiled && /var/ossec/agent_compiled/wazuh-agentd -d"
```

Or use the script:
```bash
/home/sek/wazuh/src/start_agent_fixed.sh
```

## Check Status

```bash
# Check if both are running
ps aux | grep wazuh | grep -v grep

# Check agent logs
sudo tail -f /var/ossec/agent_compiled/logs/ossec.log

# Check manager logs
sudo tail -f /var/ossec/logs/ossec.log

# Check enrollment
ls -la /var/ossec/agent_compiled/etc/client.keys
```

## Enrollment

The agent will automatically enroll with the manager. This may take a few minutes.

Watch for enrollment:
```bash
# Agent side
sudo tail -f /var/ossec/agent_compiled/logs/ossec.log | grep -i enroll

# Manager side
sudo tail -f /var/ossec/logs/ossec.log | grep -i agent
```

Once enrolled, `client.keys` will be created in `/var/ossec/agent_compiled/etc/`

## Quick Commands

### Start Services
```bash
# Manager
sudo systemctl start wazuh-manager

# Agent
sudo bash -c "cd /var/ossec/agent_compiled && export LD_LIBRARY_PATH=/var/ossec/agent_compiled && /var/ossec/agent_compiled/wazuh-agentd -d"
```

### Stop Services
```bash
# Agent
sudo pkill -f wazuh-agentd

# Manager
sudo systemctl stop wazuh-manager
```

### Check Connectivity
```bash
# Check ports
sudo netstat -tuln | grep -E "1514|1515"
# or
sudo ss -tuln | grep -E "1514|1515"
```

## Files Location

- **Agent binary**: `/var/ossec/agent_compiled/wazuh-agentd`
- **Agent config**: `/var/ossec/agent_compiled/etc/ossec.conf`
- **Agent logs**: `/var/ossec/agent_compiled/logs/ossec.log`
- **Agent keys**: `/var/ossec/agent_compiled/etc/client.keys` (created on enrollment)
- **Manager**: `/var/ossec/` (package installation)
- **Manager logs**: `/var/ossec/logs/ossec.log`

## Next Steps

1. ✅ Manager is running
2. ✅ Agent is configured
3. ⏳ Wait for agent enrollment (automatic)
4. ✅ Monitor logs for connection
5. ✅ Verify alerts are being generated

## Troubleshooting

If agent doesn't enroll:
1. Check manager is running: `sudo systemctl status wazuh-manager`
2. Check ports are listening: `sudo netstat -tuln | grep 1515`
3. Check agent logs: `sudo tail -50 /var/ossec/agent_compiled/logs/ossec.log`
4. Check manager logs: `sudo tail -50 /var/ossec/logs/ossec.log`

Version mismatch note: Agent is v5.0.0-alpha0, Manager is v4.14.1. They should still work together for basic functionality, but some features may be limited.
