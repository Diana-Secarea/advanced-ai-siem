#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 24.04 host (Hetzner/netcup/any VPS, x86 or arm64)
# up to the point where infra/deploy/DEPLOYMENT.md takes over.
#
#   scp this file root@SERVER:/root/ && ssh root@SERVER 'bash bootstrap-server.sh'
#
# Idempotent: safe to re-run.
set -euo pipefail

DEPLOY_USER=${DEPLOY_USER:-selenne}
SWAP_GB=${SWAP_GB:-4}
SSH_PORT=${SSH_PORT:-22}

echo "== [1/7] System update + base packages =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -yq
apt-get install -yq ca-certificates curl gnupg git ufw fail2ban \
    unattended-upgrades nginx certbot python3-certbot-nginx \
    python3-venv python3-pip htop jq

echo "== [2/7] Deploy user =="
if ! id "$DEPLOY_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" "$DEPLOY_USER"
    usermod -aG sudo "$DEPLOY_USER"
    # reuse root's authorized keys so the same SSH key works
    install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
    if [ -f /root/.ssh/authorized_keys ]; then
        install -m 600 -o "$DEPLOY_USER" -g "$DEPLOY_USER" \
            /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/authorized_keys"
    fi
fi

echo "== [3/7] SSH hardening (key-only, no root password login) =="
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/90-selenne.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
EOF
# reload if sshd runs as a service; socket-activated sshd (Ubuntu 24.10+)
# re-reads config on every connection, so nothing to do there
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

echo "== [4/7] Swap (${SWAP_GB}G) =="
if ! swapon --show | grep -q /swapfile; then
    fallocate -l "${SWAP_GB}G" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
# don't swap eagerly — only under real memory pressure (LLM working set must stay in RAM)
sysctl -w vm.swappiness=10
grep -q 'vm.swappiness' /etc/sysctl.d/90-selenne.conf 2>/dev/null || \
    echo 'vm.swappiness=10' > /etc/sysctl.d/90-selenne.conf

echo "== [5/7] Host firewall (defense-in-depth behind the cloud firewall) =="
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp comment 'ssh'
ufw allow 80/tcp  comment 'http (certbot + redirect)'
ufw allow 443/tcp comment 'https'
ufw --force enable
# NOTE: docker published ports bypass ufw — the Hetzner/netcup cloud firewall
# is the authoritative edge filter; additionally every compose service must
# publish on 127.0.0.1 only (e.g. "127.0.0.1:6333:6333").

echo "== [6/7] Docker (official repo, works on amd64 + arm64) =="
if ! command -v docker &>/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -yq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
usermod -aG docker "$DEPLOY_USER"

echo "== [7/8] Ollama (local LLM runtime, as a service) =="
# The official installer creates and enables ollama.service (Restart=always,
# dedicated 'ollama' user), so Ollama survives logout and reboot. Selenne's
# settings go in a drop-in, which an Ollama upgrade cannot revert.
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
install -d -m 755 /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/10-selenne.conf <<'EOF'
[Service]
# The daemon always runs so a RAG query can load the model on demand; this
# decides how long the weights then stay resident. 30m = warm for a working
# session, freed when idle. Use -1 to never unload (GPU / roomy host).
Environment="OLLAMA_KEEP_ALIVE=30m"
# Loopback only: an exposed 11434 is an unauthenticated inference endpoint.
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
OOMScoreAdjust=-100
Restart=always
RestartSec=3
EOF
systemctl daemon-reload
systemctl enable --now ollama
# Pull now so the first deploy is not also the first (slow) model download.
sudo -u ollama env HOME=/usr/share/ollama ollama pull "${OLLAMA_MODEL:-llama3.2}" || \
    echo "  [WARN] pull failed — run 'ollama pull llama3.2' by hand later"

echo "== [8/8] Automatic security updates + fail2ban =="
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
maxretry = 5
bantime = 1h
EOF
systemctl enable --now fail2ban

echo
echo "Bootstrap done. Next steps (as $DEPLOY_USER):"
echo "  1. git clone the monorepo into /home/$DEPLOY_USER/"
echo "  2. follow infra/deploy/DEPLOYMENT.md (venv, compose, backend.env, systemd,"
echo "     plus ollama-warmup.service so the model is resident from boot)"
echo "  2b. once the manager and backend.env exist, wire the backend's logs into"
echo "      Wazuh — without this the console shows nothing for collector"
echo "      downloads or HTTP activity:"
echo "        sudo env ENV_FILE=/etc/wazuh-ai/backend.env \\"
echo "          bash infra/deploy/wazuh/install-selenne-logging.sh"
echo "  3. certbot --nginx -d selenne.app -d www.selenne.app"
echo "  4. set AUTH_COOKIE_SECURE=1 + ALLOWED_ORIGINS=https://selenne.app in backend.env"
