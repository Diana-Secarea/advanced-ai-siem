#!/bin/bash
#
# Wazuh Setup Script - Agent and Manager Configuration
# This script sets up Wazuh to run correctly with both agent and manager
#

set -e

WAZUH_HOME="/home/sek/wazuh/src"
WAZUH_USER="wazuh"
WAZUH_GROUP="wazuh"

echo "=========================================="
echo "Wazuh Setup Script"
echo "=========================================="
echo ""

# Check if running as root for some operations
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Some operations require sudo. You may need to run parts of this script with sudo."
    echo ""
fi

# 1. Check binaries
echo "📦 Checking binaries..."
if [ -f "$WAZUH_HOME/wazuh-agentd" ]; then
    echo "✅ Agent binary found: $WAZUH_HOME/wazuh-agentd"
else
    echo "❌ Agent binary not found. Please compile first:"
    echo "   cd $WAZUH_HOME && make TARGET=agent"
    exit 1
fi

if [ -f "$WAZUH_HOME/wazuh-managerd" ]; then
    echo "✅ Manager binary found: $WAZUH_HOME/wazuh-managerd"
    MANAGER_MODE="compiled"
elif command -v wazuh-manager &> /dev/null || command -v ossec-remoted &> /dev/null; then
    echo "✅ Manager found (package installation)"
    MANAGER_MODE="package"
else
    echo "⚠️  Manager binary not found. Options:"
    echo "   1. Compile manager: cd $WAZUH_HOME && make TARGET=server"
    echo "   2. Install package: sudo apt-get install wazuh-manager"
    echo ""
    read -p "Continue with agent-only setup? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    MANAGER_MODE="none"
fi

# 2. Set up directories and permissions
echo ""
echo "📁 Setting up directories and permissions..."

# Create necessary directories
mkdir -p "$WAZUH_HOME/queue/sockets"
mkdir -p "$WAZUH_HOME/logs"
mkdir -p "$WAZUH_HOME/var/run"
mkdir -p "$WAZUH_HOME/var/sockets"
mkdir -p "$WAZUH_HOME/var/db"
mkdir -p "$WAZUH_HOME/var/diff"

# Set ownership
if command -v sudo &> /dev/null; then
    sudo chown -R $WAZUH_USER:$WAZUH_GROUP "$WAZUH_HOME/queue" 2>/dev/null || true
    sudo chown -R $WAZUH_USER:$WAZUH_GROUP "$WAZUH_HOME/logs" 2>/dev/null || true
    sudo chown -R $WAZUH_USER:$WAZUH_GROUP "$WAZUH_HOME/var" 2>/dev/null || true
    sudo chown -R $WAZUH_USER:$WAZUH_GROUP "$WAZUH_HOME/etc" 2>/dev/null || true
    echo "✅ Permissions set"
else
    echo "⚠️  Cannot set permissions without sudo"
fi

# 3. Check configuration files
echo ""
echo "⚙️  Checking configuration files..."

if [ ! -f "$WAZUH_HOME/etc/ossec.conf" ]; then
    echo "❌ Configuration file not found: $WAZUH_HOME/etc/ossec.conf"
    exit 1
fi

# Check if client.keys exists
if [ ! -f "$WAZUH_HOME/etc/client.keys" ]; then
    echo "⚠️  client.keys not found. This is needed for agent-manager authentication."
    echo "   The agent will try to auto-enroll if manager is running."
fi

# 4. Create manager configuration if needed
if [ "$MANAGER_MODE" = "compiled" ]; then
    echo ""
    echo "📝 Creating manager configuration..."
    
    if [ ! -f "$WAZUH_HOME/etc/ossec-manager.conf" ]; then
        cat > "$WAZUH_HOME/etc/ossec-manager.conf" << 'EOF'
<!--
  Wazuh - Manager - Configuration
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@wazuh.local</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <hostname>wazuh-manager</hostname>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>etc/rootcheck/system_audit_ssh.txt</system_audit>
    <system_audit>etc/rootcheck/system_audit_apparmor.txt</system_audit>
    <system_audit>etc/rootcheck/system_audit_suid_sgid.txt</system_audit>
  </rootcheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os>wheezy</os>
      <os>jessie</os>
      <os>stretch</os>
      <os>buster</os>
      <os>bullseye</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <os>5</os>
      <os>6</os>
      <os>7</os>
      <os>8</os>
      <os>9</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2015</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </wodle>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore frequency="10" timeframe="3600">yes</auto_ignore>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
      <integrity_interval>24h</integrity_interval>
    </synchronization>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/ossec.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/alerts/alerts.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/alerts/alerts.json</location>
  </localfile>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_verification>yes</ca_verification>
  </active-response>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

</ossec_config>
EOF
        echo "✅ Manager configuration created"
    else
        echo "✅ Manager configuration already exists"
    fi
fi

# 5. Create startup scripts
echo ""
echo "📜 Creating startup scripts..."

# Agent startup script
cat > "$WAZUH_HOME/start_agent.sh" << 'EOF'
#!/bin/bash
# Start Wazuh Agent

WAZUH_HOME="/home/sek/wazuh/src"
export LD_LIBRARY_PATH="$WAZUH_HOME:$LD_LIBRARY_PATH"

cd "$WAZUH_HOME"

echo "Starting Wazuh Agent..."
sudo -u wazuh bash -c "export LD_LIBRARY_PATH=$WAZUH_HOME && $WAZUH_HOME/wazuh-agentd -d"
echo "Agent started. Check logs: tail -f $WAZUH_HOME/logs/ossec.log"
EOF

# Manager startup script
if [ "$MANAGER_MODE" = "compiled" ]; then
    cat > "$WAZUH_HOME/start_manager.sh" << 'EOF'
#!/bin/bash
# Start Wazuh Manager

WAZUH_HOME="/home/sek/wazuh/src"
export LD_LIBRARY_PATH="$WAZUH_HOME:$LD_LIBRARY_PATH"

cd "$WAZUH_HOME"

echo "Starting Wazuh Manager..."
sudo -u wazuh bash -c "export LD_LIBRARY_PATH=$WAZUH_HOME && $WAZUH_HOME/wazuh-managerd -d"
echo "Manager started. Check logs: tail -f $WAZUH_HOME/logs/ossec.log"
EOF
    chmod +x "$WAZUH_HOME/start_manager.sh"
fi

chmod +x "$WAZUH_HOME/start_agent.sh"

# Stop scripts
cat > "$WAZUH_HOME/stop_agent.sh" << 'EOF'
#!/bin/bash
# Stop Wazuh Agent

echo "Stopping Wazuh Agent..."
sudo pkill -f wazuh-agentd || echo "Agent not running"
EOF

if [ "$MANAGER_MODE" = "compiled" ]; then
    cat > "$WAZUH_HOME/stop_manager.sh" << 'EOF'
#!/bin/bash
# Stop Wazuh Manager

echo "Stopping Wazuh Manager..."
sudo pkill -f wazuh-managerd || echo "Manager not running"
EOF
    chmod +x "$WAZUH_HOME/stop_manager.sh"
fi

chmod +x "$WAZUH_HOME/stop_agent.sh"

echo "✅ Startup scripts created"

# 6. Summary
echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "To start Wazuh:"
if [ "$MANAGER_MODE" = "compiled" ]; then
    echo "  1. Start Manager:  $WAZUH_HOME/start_manager.sh"
    echo "  2. Start Agent:    $WAZUH_HOME/start_agent.sh"
    echo ""
    echo "To stop Wazuh:"
    echo "  1. Stop Agent:     $WAZUH_HOME/stop_agent.sh"
    echo "  2. Stop Manager:   $WAZUH_HOME/stop_manager.sh"
elif [ "$MANAGER_MODE" = "package" ]; then
    echo "  1. Start Manager:  sudo systemctl start wazuh-manager"
    echo "  2. Start Agent:    $WAZUH_HOME/start_agent.sh"
    echo ""
    echo "To stop Wazuh:"
    echo "  1. Stop Agent:     $WAZUH_HOME/stop_agent.sh"
    echo "  2. Stop Manager:   sudo systemctl stop wazuh-manager"
else
    echo "  Start Agent:       $WAZUH_HOME/start_agent.sh"
    echo "  Stop Agent:        $WAZUH_HOME/stop_agent.sh"
fi
echo ""
echo "Check logs:"
echo "  tail -f $WAZUH_HOME/logs/ossec.log"
echo ""
echo "Check status:"
echo "  ps aux | grep wazuh"
echo ""
