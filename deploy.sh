#!/usr/bin/env bash
# =============================================================================
# deploy.sh — EMC Auth Server — EC2 Ubuntu deployment
#
# Stack : Docker Compose · Nginx (reverse proxy) · Certbot (Let's Encrypt)
#         AWS Secrets Manager (.env source) · AWS Route 53 (DNS A record)
#
# Usage:
#   sudo bash deploy.sh --setup          # install host deps (once)
#   sudo bash deploy.sh --create-secret  # bootstrap Secrets Manager secret (once)
#   sudo bash deploy.sh --all            # full first-time provisioning
#   sudo bash deploy.sh --deploy         # redeploy after a code/config change
#   sudo bash deploy.sh --ssl            # request / renew TLS cert
#   sudo bash deploy.sh --route53        # point Route 53 A record at this EC2 IP
#
# EC2 IAM role must have:
#   secretsmanager:GetSecretValue / DescribeSecret   on the secret ARN
#   secretsmanager:CreateSecret  / PutSecretValue    (only for --create-secret)
#   route53:ListHostedZones / ListHostedZonesByName  on *
#   route53:ChangeResourceRecordSets                 on the hosted zone
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — edit before running
# ─────────────────────────────────────────────────────────────────────────────
APP_NAME="emc-auth-server"
APP_USER="emc-auth"
APP_DIR="/opt/${APP_NAME}"
APP_SRC="${APP_DIR}/src"
ENV_FILE="${APP_DIR}/.env"
APP_PORT="8080"

REPO_URL="https://github.com/Engineersmind/emc-auth-server.git"
REPO_BRANCH="main"

DOMAIN="auth.senie.ai"
CERTBOT_EMAIL="devops@engineersmind.com"

AWS_REGION="us-east-1"
SECRET_NAME="emc-auth-server/production"   # Secrets Manager secret name/ID
HOSTED_ZONE_NAME="senie.ai."               # Route 53 zone name (trailing dot!)

COMPOSE_BASE="${APP_SRC}/infra/docker-compose.prod.yml"
COMPOSE_OVERRIDE="${APP_SRC}/infra/docker-compose.ec2.override.yml"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() {
  echo
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════${NC}"
  echo -e "${CYAN}${BOLD}  $*${NC}"
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════${NC}"
}

require_root() {
  [[ $EUID -eq 0 ]] || { error "Run as root or with sudo."; exit 1; }
}

compose_cmd() {
  docker compose \
    -f "${COMPOSE_BASE}" \
    -f "${COMPOSE_OVERRIDE}" \
    --env-file "${ENV_FILE}" \
    --project-name "${APP_NAME}" \
    "$@"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. SETUP — install all host dependencies
# ─────────────────────────────────────────────────────────────────────────────
setup_system() {
  section "System Setup"

  info "Updating package lists..."
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
  apt-get install -y -qq \
    curl wget git ca-certificates gnupg lsb-release \
    openssl jq unzip ufw fail2ban

  _install_docker
  _install_nginx
  _install_certbot
  _install_awscli
  _configure_firewall
  _setup_app_user

  info "Setup complete."
}

_install_docker() {
  if command -v docker &>/dev/null; then
    info "Docker already installed — skipping."
    return
  fi
  info "Installing Docker CE..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  info "Docker $(docker --version | head -1) installed."
}

_install_nginx() {
  if command -v nginx &>/dev/null; then
    info "Nginx already installed — skipping."
    return
  fi
  info "Installing Nginx..."
  apt-get install -y -qq nginx
  systemctl enable nginx
}

_install_certbot() {
  if command -v certbot &>/dev/null; then
    info "Certbot already installed — skipping."
    return
  fi
  info "Installing Certbot..."
  apt-get install -y -qq certbot python3-certbot-nginx
}

_install_awscli() {
  if command -v aws &>/dev/null; then
    info "AWS CLI already installed — skipping."
    return
  fi
  info "Installing AWS CLI v2..."
  local arch; arch=$(uname -m)
  wget -q "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -O /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2
  /tmp/awscliv2/aws/install --update
  rm -rf /tmp/awscliv2 /tmp/awscliv2.zip
  info "AWS CLI $(aws --version 2>&1) installed."
}

_configure_firewall() {
  info "Configuring UFW..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 'Nginx Full'
  ufw --force enable
  info "Firewall: SSH + HTTP/HTTPS open."
}

_setup_app_user() {
  if ! id "${APP_USER}" &>/dev/null; then
    info "Creating system user ${APP_USER}..."
    useradd --system --create-home --shell /bin/bash \
      --comment "EMC Auth Server service account" "${APP_USER}"
  fi
  usermod -aG docker "${APP_USER}" 2>/dev/null || true
  mkdir -p "${APP_DIR}"
  chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. SECRETS — fetch from AWS Secrets Manager, write .env
#
# Expected secret format (JSON string):
# {
#   "POSTGRES_USER":       "emc_auth",
#   "POSTGRES_PASSWORD":   "...",
#   "POSTGRES_DB":         "emc_auth",
#   "DATABASE_URL":        "postgres://emc_auth:PASS@postgres:5432/emc_auth?sslmode=disable",
#   "REDIS_PASSWORD":      "...",
#   "REDIS_URL":           "redis://:PASS@redis:6379",
#   "JWT_SECRET":          "...",
#   "JWT_ACCESS_TTL":      "3600",
#   "JWT_REFRESH_TTL":     "2592000",
#   "TOTP_ENCRYPTION_KEY": "...",
#   "SEED_ADMIN_PASSWORD": "...",
#   "SMTP_HOST":           "smtp.sendgrid.net",
#   "SMTP_PORT":           "587",
#   "SMTP_USER":           "apikey",
#   "SMTP_PASSWORD":       "...",
#   "EMAIL_FROM":          "noreply@engineersmind.com",
#   "LOG_LEVEL":           "info"
# }
# ─────────────────────────────────────────────────────────────────────────────
pull_secrets() {
  section "Secrets Manager"

  info "Fetching '${SECRET_NAME}' from ${AWS_REGION}..."

  local secret_json
  if ! secret_json=$(aws secretsmanager get-secret-value \
        --secret-id "${SECRET_NAME}" \
        --region    "${AWS_REGION}" \
        --query     'SecretString' \
        --output    text 2>&1); then
    error "Failed to fetch secret: ${secret_json}"
    error ""
    error "Check that:"
    error "  1. EC2 IAM role has secretsmanager:GetSecretValue on '${SECRET_NAME}'"
    error "  2. The secret exists in region '${AWS_REGION}'"
    error "  3. Run:  sudo bash deploy.sh --create-secret  to create it"
    exit 1
  fi

  # Validate it is valid JSON
  if ! echo "${secret_json}" | jq empty 2>/dev/null; then
    error "Secret value is not valid JSON. Re-check the secret in the console."
    exit 1
  fi

  info "Writing ${ENV_FILE}..."
  # Convert JSON {key: value} → KEY=value
  echo "${secret_json}" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > "${ENV_FILE}"

  # Append deployment-level overrides (not stored in the secret)
  cat >> "${ENV_FILE}" <<ENVEOF

# --- auto-appended by deploy.sh ---
ENV=production
PORT=${APP_PORT}
JWT_ISSUER=https://${DOMAIN}
JWT_AUDIENCE=https://${DOMAIN}
APP_BASE_URL=https://${DOMAIN}
ENVEOF

  chown "${APP_USER}:${APP_USER}" "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
  info ".env written ($(wc -l < "${ENV_FILE}") vars, chmod 600)."
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. SOURCE — clone or fast-forward
# ─────────────────────────────────────────────────────────────────────────────
update_source() {
  section "Source Code"

  if [[ -d "${APP_SRC}/.git" ]]; then
    info "Updating repo at ${APP_SRC}..."
    sudo -u "${APP_USER}" git -C "${APP_SRC}" fetch --all --prune
    sudo -u "${APP_USER}" git -C "${APP_SRC}" reset --hard "origin/${REPO_BRANCH}"
  else
    info "Cloning ${REPO_URL} (${REPO_BRANCH})..."
    mkdir -p "${APP_SRC}"
    sudo -u "${APP_USER}" git clone \
      --branch "${REPO_BRANCH}" \
      --depth  1 \
      "${REPO_URL}" "${APP_SRC}"
  fi

  chown -R "${APP_USER}:${APP_USER}" "${APP_SRC}"
  info "Source ready."
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. COMPOSE HELPERS — write override + prometheus stub
# ─────────────────────────────────────────────────────────────────────────────
write_compose_override() {
  mkdir -p "$(dirname "${COMPOSE_OVERRIDE}")"
  cat > "${COMPOSE_OVERRIDE}" <<YAML
# EC2 overlay — generated by deploy.sh
# Overrides: bind app to localhost only, build locally instead of pulling GHCR.
services:
  app:
    build:
      context: ..
      dockerfile: Dockerfile
    image: ${APP_NAME}:latest
    ports:
      - "127.0.0.1:${APP_PORT}:${APP_PORT}"
  # Restrict monitoring ports to localhost (nginx proxies /internal/*)
  prometheus:
    ports:
      - "127.0.0.1:9090:9090"
  grafana:
    ports:
      - "127.0.0.1:3000:3000"
YAML
  info "Compose override written: ${COMPOSE_OVERRIDE}"
}

write_prometheus_config() {
  local prom_dir="${APP_SRC}/infra/prometheus"
  local prom_cfg="${prom_dir}/prometheus.yml"
  if [[ -f "${prom_cfg}" ]]; then
    info "prometheus.yml already exists — skipping."
    return
  fi
  mkdir -p "${prom_dir}"
  cat > "${prom_cfg}" <<YAML
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "${APP_NAME}"
    static_configs:
      - targets: ["app:${APP_PORT}"]
    metrics_path: /metrics
YAML
  info "Minimal prometheus.yml created."
}

write_grafana_stubs() {
  local provisioning="${APP_SRC}/infra/grafana/provisioning"
  [[ -d "${provisioning}" ]] && return
  mkdir -p \
    "${provisioning}/datasources" \
    "${provisioning}/dashboards" \
    "${APP_SRC}/infra/grafana/dashboards"
  cat > "${provisioning}/datasources/prometheus.yml" <<YAML
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
YAML
  info "Grafana provisioning stubs created."
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. DOCKER COMPOSE — build and start
# ─────────────────────────────────────────────────────────────────────────────
deploy_compose() {
  section "Docker Compose"

  write_compose_override
  write_prometheus_config
  write_grafana_stubs

  info "Building image and starting services..."
  compose_cmd up -d --build --remove-orphans

  info "Waiting for app health check..."
  local attempt=0
  until curl -sf "http://127.0.0.1:${APP_PORT}/health" &>/dev/null; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge 40 ]]; then
      error "App did not become healthy after 120 s. Logs:"
      compose_cmd logs --tail 60 app
      exit 1
    fi
    sleep 3
  done

  info "App is healthy."
  compose_cmd ps
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. NGINX — write HTTP config (certbot will upgrade to HTTPS)
# ─────────────────────────────────────────────────────────────────────────────
setup_nginx() {
  section "Nginx"

  local site="/etc/nginx/sites-available/${APP_NAME}"
  mkdir -p /var/www/certbot

  cat > "${site}" <<NGINX
# EMC Auth Server — managed by deploy.sh
# HTTPS block is added automatically by certbot.
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
        proxy_pass         http://emc_auth_backend;
        proxy_http_version 1.1;
        proxy_set_header   Connection       "";
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout  120s;
        proxy_send_timeout  120s;
        proxy_buffering     off;
    }
}
NGINX

  ln -sf "${site}" "/etc/nginx/sites-enabled/${APP_NAME}"
  rm -f /etc/nginx/sites-enabled/default

  nginx -t
  systemctl reload nginx
  info "Nginx HTTP config active for ${DOMAIN}."
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. CERTBOT — issue / renew Let's Encrypt certificate
# ─────────────────────────────────────────────────────────────────────────────
setup_ssl() {
  section "SSL Certificate (Let's Encrypt)"

  if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
    info "Renewing existing certificate for ${DOMAIN}..."
    certbot renew --nginx --non-interactive --quiet
    systemctl reload nginx
    info "Certificate renewed."
    return
  fi

  info "Requesting new certificate for ${DOMAIN}..."
  certbot --nginx \
    --non-interactive \
    --agree-tos \
    --email       "${CERTBOT_EMAIL}" \
    --domains     "${DOMAIN}" \
    --redirect

  # Ensure auto-renewal timer is enabled
  systemctl enable --now certbot.timer 2>/dev/null || true

  nginx -t && systemctl reload nginx
  info "SSL active. Auto-renewal timer enabled."
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. ROUTE 53 — upsert A record to this EC2 instance's public IP
# ─────────────────────────────────────────────────────────────────────────────
update_route53() {
  section "Route 53 DNS"

  # IMDSv2: get public IP
  local token public_ip
  token=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
  if [[ -n "${token}" ]]; then
    public_ip=$(curl -sf \
      -H "X-aws-ec2-metadata-token: ${token}" \
      "http://169.254.169.254/latest/meta-data/public-ipv4")
  else
    public_ip=$(curl -sf "https://checkip.amazonaws.com")
  fi

  if [[ -z "${public_ip:-}" ]]; then
    error "Could not determine public IP. Not running on EC2, or metadata endpoint blocked."
    return 1
  fi
  info "Public IP: ${public_ip}"

  # Look up hosted zone ID from zone name
  local zone_id
  zone_id=$(aws route53 list-hosted-zones-by-name \
    --dns-name    "${HOSTED_ZONE_NAME}" \
    --region      "${AWS_REGION}" \
    --query       "HostedZones[?Name=='${HOSTED_ZONE_NAME}'].Id" \
    --output      text \
    | sed 's|/hostedzone/||')

  if [[ -z "${zone_id:-}" ]]; then
    error "No Route 53 hosted zone found for '${HOSTED_ZONE_NAME}'."
    error "Create the zone first, then re-run:  sudo bash deploy.sh --route53"
    return 1
  fi
  info "Hosted Zone ID: ${zone_id}"

  # Build change batch with jq (safe escaping)
  local change_batch
  change_batch=$(jq -n \
    --arg name "${DOMAIN}." \
    --arg ip   "${public_ip}" \
    '{
      Comment: "Upserted by deploy.sh",
      Changes: [{
        Action: "UPSERT",
        ResourceRecordSet: {
          Name: $name,
          Type: "A",
          TTL:  300,
          ResourceRecords: [{ Value: $ip }]
        }
      }]
    }')

  local change_id
  change_id=$(aws route53 change-resource-record-sets \
    --hosted-zone-id "${zone_id}" \
    --change-batch   "${change_batch}" \
    --region         "${AWS_REGION}" \
    --query          'ChangeInfo.Id' \
    --output         text)

  info "A record: ${DOMAIN} → ${public_ip} (TTL 300s)"
  info "Change ID: ${change_id}  (propagates in < 60 s)"
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: --create-secret — one-time bootstrap of Secrets Manager secret
# ─────────────────────────────────────────────────────────────────────────────
create_secret() {
  section "Create Secrets Manager Secret"

  command -v aws &>/dev/null || { error "AWS CLI not installed. Run --setup first."; exit 1; }
  command -v jq  &>/dev/null || { error "jq not installed. Run --setup first."; exit 1; }

  # Generate strong random credentials
  local pg_pass redis_pass jwt_secret totp_key
  pg_pass=$(openssl rand -base64 32 | tr -d /=+)
  redis_pass=$(openssl rand -base64 32 | tr -d /=+)
  jwt_secret=$(openssl rand -base64 48 | tr -d /=+)
  totp_key=$(openssl rand -hex 32)

  local secret_value
  secret_value=$(jq -n \
    --arg pgp  "${pg_pass}" \
    --arg rp   "${redis_pass}" \
    --arg jwt  "${jwt_secret}" \
    --arg totp "${totp_key}" \
    '{
      POSTGRES_USER:       "emc_auth",
      POSTGRES_PASSWORD:   $pgp,
      POSTGRES_DB:         "emc_auth",
      DATABASE_URL:        ("postgres://emc_auth:" + $pgp + "@postgres:5432/emc_auth?sslmode=disable"),
      REDIS_PASSWORD:      $rp,
      REDIS_URL:           ("redis://:" + $rp + "@redis:6379"),
      JWT_SECRET:          $jwt,
      JWT_ACCESS_TTL:      "3600",
      JWT_REFRESH_TTL:     "2592000",
      TOTP_ENCRYPTION_KEY: $totp,
      SEED_ADMIN_PASSWORD: "ChangeMe123!",
      SMTP_HOST:           "smtp.sendgrid.net",
      SMTP_PORT:           "587",
      SMTP_USER:           "apikey",
      SMTP_PASSWORD:       "REPLACE_WITH_SENDGRID_KEY",
      EMAIL_FROM:          "noreply@engineersmind.com",
      LOG_LEVEL:           "info",
      GRAFANA_PASSWORD:    "changeme"
    }')

  # Check if secret already exists
  if aws secretsmanager describe-secret \
       --secret-id "${SECRET_NAME}" \
       --region    "${AWS_REGION}" &>/dev/null; then
    warn "Secret '${SECRET_NAME}' already exists."
    read -rp "  Overwrite with newly generated credentials? (y/N): " answer
    [[ "${answer}" =~ ^[Yy]$ ]] || { info "Aborted — existing secret unchanged."; return; }
    aws secretsmanager put-secret-value \
      --secret-id     "${SECRET_NAME}" \
      --region        "${AWS_REGION}" \
      --secret-string "${secret_value}"
    info "Secret updated."
  else
    aws secretsmanager create-secret \
      --name          "${SECRET_NAME}" \
      --region        "${AWS_REGION}" \
      --description   "EMC Auth Server production environment variables" \
      --secret-string "${secret_value}"
    info "Secret '${SECRET_NAME}' created in ${AWS_REGION}."
  fi

  warn "Action required: update SMTP_PASSWORD and SEED_ADMIN_PASSWORD in the AWS console"
  warn "  Console: https://${AWS_REGION}.console.aws.amazon.com/secretsmanager/secret?name=${SECRET_NAME}&region=${AWS_REGION}"
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
  local ssl_status="pending — run:  sudo bash deploy.sh --ssl"
  [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]] \
    && ssl_status="active (auto-renewal enabled)"

  echo
  echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║        EMC Auth Server — Deployment Complete          ║${NC}"
  echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
  echo
  echo "  URL         :  https://${DOMAIN}"
  echo "  Health      :  https://${DOMAIN}/health"
  echo "  Swagger     :  https://${DOMAIN}/swagger/index.html"
  echo "  Metrics     :  https://${DOMAIN}/metrics"
  echo "  SSL         :  ${ssl_status}"
  echo
  echo "  Admin login :  admin@emc.local  /  see SEED_ADMIN_PASSWORD in Secrets Manager"
  echo
  echo "  Logs        :  docker compose -f ${COMPOSE_BASE} -f ${COMPOSE_OVERRIDE} \\"
  echo "                   --project-name ${APP_NAME} logs -f app"
  echo
  echo "  Containers  :  docker compose ... ps"
  echo "  Restart app :  docker compose ... restart app"
  echo "  Redeploy    :  sudo bash ${APP_SRC}/deploy.sh --deploy"
  echo
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF

  ${BOLD}Usage:${NC} sudo bash deploy.sh <COMMAND>

  ${BOLD}Commands:${NC}
    --all             Full first-time provisioning (setup + secret + deploy + ssl + route53)
    --setup           Install Docker, Nginx, Certbot, AWS CLI on the host
    --create-secret   Generate and store credentials in AWS Secrets Manager
    --deploy          Pull secrets, update source, docker compose up, configure nginx
    --ssl             Issue / renew Let's Encrypt certificate for ${DOMAIN}
    --route53         Upsert Route 53 A record to this EC2's public IP
    --help            Show this message

EOF
  exit 1
}

require_root

case "${1:-}" in
  --setup)          setup_system ;;
  --create-secret)  create_secret ;;
  --deploy)
    pull_secrets
    update_source
    deploy_compose
    setup_nginx
    print_summary
    ;;
  --ssl)            setup_ssl ;;
  --route53)        update_route53 ;;
  --all)
    setup_system
    create_secret
    pull_secrets
    update_source
    deploy_compose
    setup_nginx
    update_route53
    setup_ssl
    print_summary
    ;;
  --help|-h|*)      usage ;;
esac
