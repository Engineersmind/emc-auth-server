#!/usr/bin/env bash
# =============================================================================
# 02-deploy.sh — Clone repo, pull secrets, build image, start Docker Compose
#
# Prerequisites:
#   - 01-setup.sh completed
#   - dev/EMC_Auth secret populated in AWS Secrets Manager
#   - EC2 IAM role has secretsmanager:GetSecretValue
#
# Usage: sudo bash /opt/emc-auth/src/scripts/02-deploy.sh
# Safe to re-run — pulls latest code and restarts containers.
# =============================================================================
set -euo pipefail

APP_NAME="${APP_NAME:-emc-auth}"
APP_USER="${APP_USER:-emc-auth}"
APP_DIR="${APP_DIR:-/opt/${APP_NAME}}"
APP_SRC="${APP_DIR}/src"
ENV_FILE="${APP_DIR}/.env"
APP_PORT="${APP_PORT:-8080}"

AWS_REGION="${AWS_REGION:-us-east-1}"
SECRET_NAME="${SECRET_NAME:-dev/EMC_Auth}"
DOMAIN="${DOMAIN:-auth.senie.ai}"
REPO_URL="${REPO_URL:-https://github.com/Engineersmind/emc-auth-server.git}"
REPO_BRANCH="${REPO_BRANCH:-master}"
ECR_IMAGE_URI="${ECR_IMAGE_URI:-}"   # leave empty to build locally

COMPOSE_BASE="${APP_SRC}/infra/docker-compose.prod.yml"
COMPOSE_OVR="${APP_SRC}/infra/docker-compose.ec2.override.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[deploy]${NC} $*"; }
error() { echo -e "${RED}[deploy]${NC} $*" >&2; }

[[ $EUID -eq 0 ]] || { error "Run as root: sudo bash $0"; exit 1; }

# ── 1. Clone / update source ─────────────────────────────────────────────────
info "Updating source code..."
mkdir -p "${APP_DIR}"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

if [[ -d "${APP_SRC}/.git" ]]; then
  sudo -u "${APP_USER}" git -C "${APP_SRC}" fetch --all --prune
  sudo -u "${APP_USER}" git -C "${APP_SRC}" reset --hard "origin/${REPO_BRANCH}"
else
  sudo -u "${APP_USER}" git clone \
    --branch "${REPO_BRANCH}" --depth 1 \
    "${REPO_URL}" "${APP_SRC}"
fi
chown -R "${APP_USER}:${APP_USER}" "${APP_SRC}"

# ── 2. Pull secrets from AWS Secrets Manager → .env ──────────────────────────
info "Fetching secret: ${SECRET_NAME} (${AWS_REGION})..."
SECRET_JSON=$(aws secretsmanager get-secret-value \
  --secret-id  "${SECRET_NAME}" \
  --region     "${AWS_REGION}" \
  --query      'SecretString' \
  --output     text)

if [[ -z "${SECRET_JSON}" ]]; then
  error "Empty secret returned. Populate ${SECRET_NAME} in AWS Console first."
  exit 1
fi

echo "${SECRET_JSON}" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > "${ENV_FILE}"

# Append runtime values
cat >> "${ENV_FILE}" <<ENVEOF

# Auto-appended by 02-deploy.sh
ENV=production
PORT=${APP_PORT}
JWT_ISSUER=https://${DOMAIN}
JWT_AUDIENCE=https://${DOMAIN}
APP_BASE_URL=https://${DOMAIN}
ENVEOF

chown "${APP_USER}:${APP_USER}" "${ENV_FILE}"
chmod 600 "${ENV_FILE}"
info ".env written ($(wc -l < "${ENV_FILE}") vars)."

# ── 3. Write docker-compose EC2 override ─────────────────────────────────────
info "Writing compose override..."
cat > "${APP_SRC}/infra/docker-compose.ec2.override.yml" <<YAML
# EC2 overlay — managed by 02-deploy.sh
# Monitoring disabled — handled by DevOps Copilot.
services:
  app:
    image: "${ECR_IMAGE_URI:-${APP_NAME}:latest}"
    ports:
      - "127.0.0.1:${APP_PORT}:${APP_PORT}"
  prometheus:
    profiles: ["disabled"]
  grafana:
    profiles: ["disabled"]
YAML
chown "${APP_USER}:${APP_USER}" "${APP_SRC}/infra/docker-compose.ec2.override.yml"

# ── 4. Build or pull image ────────────────────────────────────────────────────
if [[ -n "${ECR_IMAGE_URI}" ]]; then
  info "Logging in to ECR and pulling ${ECR_IMAGE_URI}..."
  ECR_HOST=$(echo "${ECR_IMAGE_URI}" | cut -d/ -f1)
  aws ecr get-login-password --region "${AWS_REGION}" \
    | docker login --username AWS --password-stdin "${ECR_HOST}"
  docker pull "${ECR_IMAGE_URI}"
else
  info "Building Docker image locally (no ECR_IMAGE_URI set)..."
  cd "${APP_SRC}"
  docker build -t "${APP_NAME}:latest" .
fi

# ── 5. Start docker compose ───────────────────────────────────────────────────
info "Starting containers..."
docker compose \
  -f "${COMPOSE_BASE}" \
  -f "${COMPOSE_OVR}" \
  --env-file "${ENV_FILE}" \
  --project-name "${APP_NAME}" \
  up -d --remove-orphans

# ── 6. Health check ───────────────────────────────────────────────────────────
info "Waiting for app health check..."
for i in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:${APP_PORT}/health" &>/dev/null; then
    info "App healthy after ${i} attempts."
    break
  fi
  [[ $i -eq 40 ]] && { error "App did not become healthy. Check logs:"; docker compose -f "${COMPOSE_BASE}" -f "${COMPOSE_OVR}" --project-name "${APP_NAME}" logs --tail 50 app; exit 1; }
  sleep 3
done

info "02-deploy.sh complete."
echo ""
echo "  App running at : http://127.0.0.1:${APP_PORT}"
echo "  Health check   : http://127.0.0.1:${APP_PORT}/health"
echo ""
echo "  Next: point Route 53 A record to this IP, then run:"
echo "    sudo bash ${APP_SRC}/scripts/03-nginx-certbot.sh"
