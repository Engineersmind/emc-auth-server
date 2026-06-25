#!/usr/bin/env bash
# =============================================================================
# 03-nginx-certbot.sh — Configure Nginx reverse proxy + Let's Encrypt SSL
#
# Prerequisites:
#   - 01-setup.sh and 02-deploy.sh completed (app must be running on :8080)
#   - DNS A record for DOMAIN already points to this server's public IP
#   - Port 80 and 443 open in the security group
#
# Usage: sudo bash /opt/emc-auth/src/scripts/03-nginx-certbot.sh
# Safe to re-run — certbot renews if cert already exists.
# =============================================================================
set -euo pipefail

APP_NAME="${APP_NAME:-emc-auth}"
APP_PORT="${APP_PORT:-8080}"
DOMAIN="${DOMAIN:-auth.senie.ai}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-devops@engineersmind.com}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[nginx]${NC} $*"; }
warn()  { echo -e "${YELLOW}[nginx]${NC} $*"; }
error() { echo -e "${RED}[nginx]${NC} $*" >&2; }

[[ $EUID -eq 0 ]] || { error "Run as root: sudo bash $0"; exit 1; }

# Verify app is running before touching nginx
if ! curl -sf "http://127.0.0.1:${APP_PORT}/health" &>/dev/null; then
  error "App is not responding on port ${APP_PORT}."
  error "Run 02-deploy.sh first."
  exit 1
fi

# ── 1. Nginx HTTP config (certbot will upgrade to HTTPS) ─────────────────────
info "Writing nginx config for ${DOMAIN}..."
NGINX_SITE="/etc/nginx/sites-available/${APP_NAME}"
mkdir -p /var/www/certbot

cat > "${NGINX_SITE}" <<NGINX
upstream emc_auth_backend {
    server 127.0.0.1:${APP_PORT};
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # Certbot ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass          http://emc_auth_backend;
        proxy_http_version  1.1;
        proxy_set_header    Connection        "";
        proxy_set_header    Host              \$host;
        proxy_set_header    X-Real-IP         \$remote_addr;
        proxy_set_header    X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto \$scheme;
        proxy_read_timeout  120s;
        proxy_send_timeout  120s;
        proxy_buffering     off;
    }
}
NGINX

ln -sf "${NGINX_SITE}" "/etc/nginx/sites-enabled/${APP_NAME}"
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl reload nginx
info "Nginx HTTP config active."

# ── 2. Let's Encrypt SSL ─────────────────────────────────────────────────────
if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
  info "Certificate already exists — renewing if needed..."
  certbot renew --nginx --non-interactive --quiet
else
  info "Requesting certificate for ${DOMAIN}..."
  certbot --nginx \
    --non-interactive \
    --agree-tos \
    --email   "${CERTBOT_EMAIL}" \
    --domains "${DOMAIN}" \
    --redirect
fi

# Enable auto-renewal
systemctl enable --now certbot.timer 2>/dev/null || true

nginx -t && systemctl reload nginx

info "03-nginx-certbot.sh complete."
echo ""
echo "  App : https://${DOMAIN}"
echo "  Health : https://${DOMAIN}/health"
echo "  Swagger: https://${DOMAIN}/swagger/index.html"
