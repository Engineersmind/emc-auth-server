#!/usr/bin/env bash
# =============================================================================
# deploy-ecr.sh — Pull ECR image, fetch secrets, restart app container
#
# Usage: bash /opt/emc-auth/src/scripts/deploy-ecr.sh \
#            <IMAGE_URI> <SECRET_NAME> <REGION> <DOMAIN>
#
# Called by GitHub Actions CI/CD via SSM Run Command.
# =============================================================================
set -euo pipefail

IMAGE_URI="${1:?IMAGE_URI required}"
SECRET_NAME="${2:?SECRET_NAME required}"
REGION="${3:?REGION required}"
DOMAIN="${4:?DOMAIN required}"

APP_CONTAINER="emc-auth-app"
REDIS_CONTAINER="emc-auth-redis"
NETWORK="emc-auth-net"

echo "[deploy] Image   : $IMAGE_URI"
echo "[deploy] Secret  : $SECRET_NAME"
echo "[deploy] Domain  : $DOMAIN"

# 1. ECR login
ECR_HOST=$(echo "$IMAGE_URI" | cut -d/ -f1)
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$ECR_HOST"

# 2. Pull image
docker pull "$IMAGE_URI"

# 3. Fetch secrets → /tmp/app.env
aws secretsmanager get-secret-value \
  --secret-id  "$SECRET_NAME" \
  --region     "$REGION" \
  --query      SecretString \
  --output     text \
  | python3 -c "
import sys, json
for k, v in json.load(sys.stdin).items():
    print(k + '=' + str(v))
" > /tmp/app.env

REDIS_PASS=$(grep "^REDIS_PASSWORD=" /tmp/app.env | cut -d= -f2-)

cat >> /tmp/app.env <<ENV
ENV=production
PORT=8080
JWT_ISSUER=https://${DOMAIN}
JWT_AUDIENCE=https://${DOMAIN}
APP_BASE_URL=https://${DOMAIN}
REDIS_URL=redis://:${REDIS_PASS}@${REDIS_CONTAINER}:6379
ENV

chmod 600 /tmp/app.env
echo "[deploy] .env written ($(wc -l < /tmp/app.env) vars)"

# 4. Ensure Docker network exists
docker network create "$NETWORK" 2>/dev/null || true

# 5. Ensure Redis is running (skip if already healthy)
if ! docker ps --filter "name=^/${REDIS_CONTAINER}$" --filter status=running -q | grep -q .; then
  echo "[deploy] Starting Redis..."
  docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true
  docker run -d \
    --name "$REDIS_CONTAINER" \
    --network "$NETWORK" \
    --restart unless-stopped \
    redis:7-alpine \
    redis-server --requirepass "$REDIS_PASS" \
      --maxmemory 128mb --maxmemory-policy allkeys-lru --save ""
  sleep 3
else
  echo "[deploy] Redis already running."
fi

# 6. Replace app container
echo "[deploy] Replacing $APP_CONTAINER..."
docker rm -f "$APP_CONTAINER" 2>/dev/null || true
docker run -d \
  --name "$APP_CONTAINER" \
  --network "$NETWORK" \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  --env-file /tmp/app.env \
  "$IMAGE_URI"

# 7. Health check
echo "[deploy] Waiting for health check..."
for i in $(seq 1 24); do
  if curl -sf http://127.0.0.1:8080/health &>/dev/null; then
    echo "[deploy] App healthy after ${i} attempts."
    break
  fi
  [[ $i -eq 24 ]] && { echo "[deploy] Health check timed out."; docker logs "$APP_CONTAINER" --tail 30; exit 1; }
  sleep 5
done

# 8. Clean up old images
docker image prune -f --filter until=24h

echo "[deploy] Done. Image: $IMAGE_URI"
