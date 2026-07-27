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

echo "== [7/7] Automatic security updates + fail2ban =="
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
echo "  2. follow infra/deploy/DEPLOYMENT.md (venv, compose, backend.env, systemd)"
echo "  3. certbot --nginx -d selenne.app -d www.selenne.app"
echo "  4. set AUTH_COOKIE_SECURE=1 + ALLOWED_ORIGINS=https://selenne.app in backend.env"
