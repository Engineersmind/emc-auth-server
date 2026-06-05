#!/usr/bin/env bash
set -e

IMAGE_URI="$1"
SECRET_NAME="$2"
REGION="$3"
DOMAIN="$4"

# Pull image
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$(echo "$IMAGE_URI" | cut -d/ -f1)"
docker pull "$IMAGE_URI"

# Fetch secrets → env file
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" --region "$REGION" \
  --query SecretString --output text \
  | python3 -c "import sys,json; [print(k+'='+str(v)) for k,v in json.load(sys.stdin).items()]" \
  > /tmp/app.env

REDIS_PASS=$(grep "^REDIS_PASSWORD=" /tmp/app.env | cut -d= -f2-)
echo "REDIS_URL=redis://:${REDIS_PASS}@emc-auth-redis:6379" >> /tmp/app.env
echo "ENV=production" >> /tmp/app.env
echo "PORT=8080" >> /tmp/app.env
echo "JWT_ISSUER=https://${DOMAIN}" >> /tmp/app.env
echo "APP_BASE_URL=https://${DOMAIN}" >> /tmp/app.env

# Restart app
docker rm -f emc-auth-app 2>/dev/null || true
docker run -d \
  --name emc-auth-app \
  --network emc-auth-net \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  --env-file /tmp/app.env \
  "$IMAGE_URI"

echo "Done: $IMAGE_URI"
