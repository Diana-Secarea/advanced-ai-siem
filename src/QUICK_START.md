# Wazuh Quick Start Guide

## Current Setup

- **Agent**: Compiled from source (v5.0.0-alpha0) at `/home/sek/wazuh/src`
- **Manager**: Package installation (v4.14.1) at `/var/ossec`

⚠️ **Version Mismatch**: The compiled agent (v5.0.0-alpha0) may not be compatible with the package manager (v4.14.1). The agent may need to auto-enroll or you may need to compile the manager from the same source.

## Step-by-Step Setup

### 0. One-time: make agent and config work every time (recommended)

Run once so you can start the agent and edit `etc/ossec.conf` without permission issues:

```bash
cd /home/sek/wazuh/src
sudo ./setup_agent_for_user.sh
```

This gives your user ownership of `etc/`, `queue/`, `logs/`, `var/` and adds logging to `ossec.conf`. After this, `./start_agent.sh` and editing the config work every time.

### 1. Run Setup Script

```bash
cd /home/sek/wazuh/src
./setup_wazuh.sh
```

This will:
- Check binaries
- Set up directories and permissions
- Create configuration files
- Create startup scripts

### 2. Set Up Authentication

```bash
./setup_authentication.sh
```

This will guide you through agent-manager authentication.

### 3. Start Manager (Package)

```bash
# Check if manager is running
sudo systemctl status wazuh-manager

# Start manager if not running
sudo systemctl start wazuh-manager

# Enable auto-start on boot
sudo systemctl enable wazuh-manager
```

### 4. Start Agent

```bash
./start_agent.sh
```

The agent will:
- Connect to manager at `127.0.0.1:1514`
- Auto-enroll if authentication is not set up
- Start collecting logs and events

### 5. Check Status

```bash
./check_status.sh
```

This shows:
- Agent status
- Manager status
- Authentication status
- Connectivity
- Log locations

## Troubleshooting

### Agent won't start

1. Check permissions:
```bash
sudo chown -R wazuh:wazuh /home/sek/wazuh/src/queue
sudo chown -R wazuh:wazuh /home/sek/wazuh/src/logs
sudo chown -R wazuh:wazuh /home/sek/wazuh/src/var
```

2. Check logs:
```bash
tail -50 /home/sek/wazuh/src/logs/ossec.log
```

3. Check if manager is accessible:
```bash
sudo netstat -tuln | grep 1514
# or
sudo ss -tuln | grep 1514
```

### Agent can't connect to manager

1. Verify manager is running:
```bash
sudo systemctl status wazuh-manager
```

2. Check manager logs:
```bash
sudo tail -50 /var/ossec/logs/ossec.log
```

3. Verify network connectivity:
```bash
telnet 127.0.0.1 1514
# or
nc -zv 127.0.0.1 1514
```

### Authentication issues

1. Check if client.keys exists:
```bash
ls -la /home/sek/wazuh/src/etc/client.keys
```

2. If empty or missing, the agent will auto-enroll. Check logs:
```bash
tail -f /home/sek/wazuh/src/logs/ossec.log | grep -i enroll
```

3. Manual enrollment (if agent-auth is available):
```bash
# From package manager
sudo /var/ossec/bin/agent-auth -m 127.0.0.1

# Or from compiled
/home/sek/wazuh/src/agent-auth -m 127.0.0.1
```

### Version compatibility

If you see errors about version mismatch:

**Option 1**: Use compiled manager (recommended for development)
```bash
cd /home/sek/wazuh/src
make TARGET=server
./start_manager.sh
```

**Option 2**: Use package agent (if available)
```bash
sudo apt-get install wazuh-agent
sudo systemctl start wazuh-agent
```

## Useful Commands

### View Logs

```bash
# Agent logs
tail -f /home/sek/wazuh/src/logs/ossec.log

# Manager logs
sudo tail -f /var/ossec/logs/ossec.log

# Alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### Stop Services

```bash
# Stop agent
./stop_agent.sh

# Stop manager
sudo systemctl stop wazuh-manager
```

### Restart Services

```bash
# Restart agent
./stop_agent.sh && ./start_agent.sh

# Restart manager
sudo systemctl restart wazuh-manager
```

### Check Processes

```bash
ps aux | grep wazuh
```

### Check Ports

```bash
sudo netstat -tuln | grep -E "1514|55000"
# or
sudo ss -tuln | grep -E "1514|55000"
```

## Configuration Files

- **Agent config**: `/home/sek/wazuh/src/etc/ossec.conf`
- **Manager config**: `/var/ossec/etc/ossec.conf`
- **Agent keys**: `/home/sek/wazuh/src/etc/client.keys`
- **Manager keys**: `/var/ossec/etc/client.keys`

## Next Steps

1. ✅ Run setup: `./setup_wazuh.sh`
2. ✅ Set up auth: `./setup_authentication.sh`
3. ✅ Start manager: `sudo systemctl start wazuh-manager`
4. ✅ Start agent: `./start_agent.sh`
5. ✅ Check status: `./check_status.sh`
6. ✅ Monitor logs: `tail -f /home/sek/wazuh/src/logs/ossec.log`

## Support

For issues:
1. Check logs first
2. Run `./check_status.sh`
3. Verify permissions
4. Check network connectivity
5. Review configuration files
