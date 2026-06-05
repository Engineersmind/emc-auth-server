#!/usr/bin/env bash
# =============================================================================
# 01-setup.sh — System dependencies for EMC Auth Server
#
# Installs: Docker CE, AWS CLI v2, Nginx, Certbot, UFW, Fail2ban
# Creates:  emc-auth system user with docker group membership
#
# Usage: sudo bash /opt/emc-auth/src/scripts/01-setup.sh
# Runs automatically on first boot via user_data.sh
# Safe to re-run (idempotent).
# =============================================================================
set -euo pipefail

APP_NAME="${APP_NAME:-emc-auth}"
APP_USER="${APP_USER:-emc-auth}"
APP_DIR="${APP_DIR:-/opt/${APP_NAME}}"
AWS_REGION="${AWS_REGION:-us-east-1}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[setup]${NC} $*"; }
error() { echo -e "${RED}[setup]${NC} $*" >&2; }

[[ $EUID -eq 0 ]] || { error "Run as root: sudo bash $0"; exit 1; }

# ── 1. System packages ───────────────────────────────────────────────────────
info "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  curl wget git ca-certificates gnupg lsb-release \
  openssl jq unzip ufw fail2ban nginx certbot python3-certbot-nginx

# ── 2. Docker CE ─────────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
  info "Docker already installed — skipping."
else
  info "Installing Docker CE..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  # Single-line write avoids multiline heredoc corruption
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  info "Docker $(docker --version) installed."
fi

# ── 3. AWS CLI v2 ────────────────────────────────────────────────────────────
if command -v aws &>/dev/null; then
  info "AWS CLI already installed — skipping."
else
  info "Installing AWS CLI v2..."
  ARCH=$(uname -m)
  wget -q "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -O /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2
  /tmp/awscliv2/aws/install --update
  rm -rf /tmp/awscliv2 /tmp/awscliv2.zip
  info "AWS CLI $(aws --version 2>&1) installed."
fi

# ── 4. App user ──────────────────────────────────────────────────────────────
if ! id "${APP_USER}" &>/dev/null; then
  info "Creating system user ${APP_USER}..."
  useradd --system --create-home --shell /bin/bash \
    --comment "${APP_NAME} service account" "${APP_USER}"
fi
usermod -aG docker "${APP_USER}"
usermod -aG docker ubuntu 2>/dev/null || true

# AWS region config for ubuntu + app user
for U in ubuntu "${APP_USER}"; do
  HOME_DIR=$(eval echo "~${U}")
  mkdir -p "${HOME_DIR}/.aws"
  cat > "${HOME_DIR}/.aws/config" <<AWSCFG
[default]
region = ${AWS_REGION}
AWSCFG
  chown -R "${U}:${U}" "${HOME_DIR}/.aws"
done

# ── 5. App directory ─────────────────────────────────────────────────────────
mkdir -p "${APP_DIR}"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

# ── 6. Firewall ──────────────────────────────────────────────────────────────
info "Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw allow 5000/tcp  # DevOps Copilot
ufw --force enable

info "01-setup.sh complete."
echo ""
echo "  Next: sudo bash /opt/emc-auth/src/scripts/02-deploy.sh"
