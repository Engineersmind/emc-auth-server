# EMC Auth Server — Production Deployment Runbook

This runbook covers first-time production deployment, environment configuration, health verification, and common troubleshooting steps.

## Prerequisites

- Docker 24+ and Docker Compose v2+
- PostgreSQL 16 instance with a dedicated database and user
- Redis 7 instance (ElastiCache, Memorystore, or self-hosted)
- Domain name with TLS termination at load balancer or nginx reverse proxy
- `emc-auth-server` Docker image (built from this repository)

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| DATABASE_URL | Yes | — | PostgreSQL DSN e.g. `postgres://user:pass@host:5432/db?sslmode=require` |
| REDIS_URL | Yes | — | Redis URL e.g. `redis://:password@host:6379/0` |
| JWT_ISSUER | Yes | `https://auth.emc.local` | Base URL of this server placed in the `iss` JWT claim |
| APP_BASE_URL | Yes | `http://localhost:8080` | Same as JWT_ISSUER — prepended to password-reset link URLs in emails |
| SEED_ADMIN_PASSWORD | Yes | `ChangeMe123!` | First-run super-admin password — **change after first login** |
| TOTP_ENCRYPTION_KEY | Yes | — | 64-char hex AES-256 key for TOTP secret encryption. Generate: `openssl rand -hex 32` |
| PORT | No | `8080` | HTTP listen port |
| ENV | No | `development` | Set to `production` to enable HTTPS redirect and production mailer |
| LOG_LEVEL | No | `info` | Zerolog level: `debug` / `info` / `warn` / `error` |
| SMTP_HOST | No | — | SMTP server hostname (required in production for password-reset emails) |
| SMTP_PORT | No | `587` | SMTP server port (587 for STARTTLS, 465 for SSL) |
| SMTP_FROM | No | `no-reply@emc.local` | From address for outgoing emails |
| SMTP_USERNAME | No | — | SMTP authentication username |
| SMTP_PASSWORD | No | — | SMTP authentication password |

> **Note:** In development (`ENV=development`), password-reset emails are logged to the console instead of sent via SMTP. Set `ENV=production` and configure SMTP fields for real email delivery.

## First-Time Setup

### 1. Generate the TOTP encryption key

```bash
openssl rand -hex 32
# Copy the output — this is your TOTP_ENCRYPTION_KEY (64 hex characters)
```

### 2. Create .env.production (never commit to git)

```bash
cat > .env.production << 'EOF'
DATABASE_URL=postgres://emc_auth:STRONG_PASSWORD@your-db-host:5432/emc_auth?sslmode=require
REDIS_URL=redis://:STRONG_PASSWORD@your-redis-host:6379/0
JWT_ISSUER=https://auth.your-domain.com
APP_BASE_URL=https://auth.your-domain.com
SEED_ADMIN_PASSWORD=STRONG_ADMIN_PASSWORD
TOTP_ENCRYPTION_KEY=<output from openssl rand -hex 32>
ENV=production
LOG_LEVEL=info
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_FROM=no-reply@your-domain.com
SMTP_USERNAME=your-smtp-user
SMTP_PASSWORD=your-smtp-password
EOF
```

### 3. Build or pull the Docker image

```bash
docker build -t emc-auth-server:latest .
# OR pull from your registry:
# docker pull your-registry/emc-auth-server:latest
```

### 4. Start the server (migrations run automatically on startup)

```bash
docker run -d \
  --name emc-auth-server \
  --env-file .env.production \
  -p 8080:8080 \
  --restart unless-stopped \
  emc-auth-server:latest
```

### 5. Verify startup

```bash
docker logs -f emc-auth-server
# Should see: "migrations complete", "seed ... ensured", "server listening"

curl -f https://auth.your-domain.com/health
# Expected: HTTP 200 {"status":"ok"}
```

## Docker Compose (Production)

If using the production compose file:

```bash
docker-compose -f infra/docker-compose.prod.yml up -d
```

## Health Check

```bash
curl -sf https://auth.your-domain.com/health
```

Kubernetes liveness probe:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 10
```

## Security Checklist

- [ ] `SEED_ADMIN_PASSWORD` changed from default `ChangeMe123!` after first login
- [ ] `TOTP_ENCRYPTION_KEY` stored in a secrets manager (AWS Secrets Manager, HashiCorp Vault, or similar)
- [ ] `DATABASE_URL` uses `sslmode=require`
- [ ] `REDIS_URL` uses authentication (`requirepass` in Redis config)
- [ ] `SMTP_PASSWORD` stored in a secrets manager — never hardcoded in .env committed to git
- [ ] The `/metrics` endpoint is network-restricted (not publicly exposed — protect via reverse proxy or network policy)
- [ ] TLS termination at load balancer or nginx reverse proxy (`ENV=production` enables HTTPS redirect)
- [ ] Container runs as non-root (distroless:nonroot uid 65532)
- [ ] Rotate `TOTP_ENCRYPTION_KEY` via your secrets manager rotation policy
- [ ] `.env.production` file is in `.gitignore`

## Monitoring

Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: emc-auth-server
    static_configs:
      - targets: ['your-auth-server:8080']
    metrics_path: /metrics
```

Grafana dashboard: `infra/grafana/dashboard.json` (import via Grafana UI or API).
Alerting rules: `infra/prometheus/alerts.yml` (load into Prometheus).

Key metrics exposed on `/metrics`:
- `http_requests_total` — request count by method, path, status
- `http_request_duration_seconds` — request latency histogram
- `go_*` — Go runtime metrics (GC, goroutines, memory)

## Load Testing

Run the k6 load test to verify SLA compliance before going live:

```bash
# Requires k6 installed: https://k6.io/docs/getting-started/installation/
make load-test

# Or against a specific target:
BASE_URL=https://auth.your-domain.com k6 run scripts/load-test.js
```

SLA thresholds declared in `scripts/load-test.js`:
- p99 login latency ≤ 200ms (NFR-02)
- HTTP error rate < 1% (429s from rate limiter are expected and do not count as failures)
- Zero HTTP 5xx responses

## Upgrading from UUID Schema (Breaking Change)

> **This section applies only when upgrading from a deployment that ran on the `master`
> branch before the `feat/auth-refactor` merge.**

The `feat/auth-refactor` branch rewrites all primary and foreign key columns from
PostgreSQL `uuid` to `bigint generated always as identity`.  This change cannot be
applied to an existing database via `ALTER TABLE` — it touches every table, every
foreign key, and every index.

The server detects this at startup.  If `tenants.id` is still `uuid`, you will see:

```
FATAL schema incompatibility: tenants.id is type 'uuid' but this release requires 'bigint identity'.
```

### Upgrade procedure

1. **Export all application data** from the existing database before taking any further
   action (use `pg_dump` or your cloud provider's snapshot feature).

2. **Provision a fresh PostgreSQL 16 database** (or drop and recreate the existing one):
   ```bash
   psql -U postgres -c "DROP DATABASE emc_auth;"
   psql -U postgres -c "CREATE DATABASE emc_auth OWNER emc_auth_user;"
   ```

3. **Start the server** pointing at the empty database.  Goose will apply all 39
   migrations and the seed script will create the default tenant and super-admin.

4. **Re-import application data** via the Admin API or by replaying events from your
   audit log.  There is no automated data-migration script because the primary key
   type changes require reassigning all IDs.

5. **Update `SEED_ADMIN_PASSWORD`** and any client credentials stored in the old
   database — they were hashed against the old IDs and cannot be reused directly.

> **For net-new deployments** (no existing database) nothing special is required.
> The server starts, runs all migrations against the empty database, and seeds normally.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `database connection failed after 10 attempts` | Wrong DATABASE_URL or DB unreachable | Check `DATABASE_URL`, verify `pg_isready` from container network |
| `TOTP_ENCRYPTION_KEY must be 64-char hex` | Wrong key format or length | Regenerate with `openssl rand -hex 32` (produces exactly 64 hex chars) |
| `jwt_secret is empty` | Tenant row has empty jwt_secret | Reseed: update the tenant row in the database directly |
| `429 Too Many Requests` on login at high load | Rate limiter active (5 req/min/IP) — expected | Normal behavior under load test. Only 5xx is a problem. |
| `429 Too Many Requests` on non-login routes | Per-app rate limit misconfigured | Check app-limits table via `/api/v1/admin/app-limits` |
| Prometheus `/metrics` not appearing | Middleware not registered | Confirm `PrometheusMetrics()` middleware is in `routes.go` |
| Container exits immediately | Missing required env var | Run `docker logs emc-auth-server` to see the specific missing variable |
| Password-reset emails not sending | SMTP not configured | Set `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD` and `ENV=production` |
| `http: TLS handshake error` in logs | Clients hitting HTTP directly | Ensure load balancer handles TLS and sets `X-Forwarded-Proto: https` |
