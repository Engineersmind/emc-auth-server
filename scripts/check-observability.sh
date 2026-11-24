#!/usr/bin/env bash
# Observability config checks (issue #217): Prometheus config, alert rules,
# promtool unit tests, Alertmanager config, and the Go observability drift
# tests. Stops at the first failure.
#
# Uses the SAME pinned images as the monitoring profile in docker-compose.yml
# so what CI validates is what runs locally. Keep the tags in sync.
set -euo pipefail
# Git Bash (MSYS) rewrites leading-slash args like /etc/prometheus into
# Windows paths; the container paths inside -v must not be converted.
export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROM_IMAGE="prom/prometheus:v3.0.1"
AM_IMAGE="prom/alertmanager:v0.28.1"

echo "== promtool check config (prometheus.local.yml) =="
docker run --rm --entrypoint promtool \
  -v "$ROOT/infra/prometheus:/etc/prometheus:ro" \
  "$PROM_IMAGE" check config /etc/prometheus/prometheus.local.yml

echo "== promtool check rules (audit_alerts.yml, service_alerts.yml) =="
docker run --rm --entrypoint promtool \
  -v "$ROOT/infra/prometheus:/etc/prometheus:ro" \
  "$PROM_IMAGE" check rules /etc/prometheus/audit_alerts.yml /etc/prometheus/service_alerts.yml

echo "== promtool test rules (tests/service_alerts_test.yml, tests/audit_alerts_test.yml) =="
docker run --rm --entrypoint promtool \
  -v "$ROOT/infra/prometheus:/etc/prometheus:ro" \
  "$PROM_IMAGE" test rules /etc/prometheus/tests/service_alerts_test.yml /etc/prometheus/tests/audit_alerts_test.yml

echo "== amtool check-config (alertmanager.yml) =="
docker run --rm --entrypoint amtool \
  -v "$ROOT/infra/alertmanager:/etc/alertmanager:ro" \
  "$AM_IMAGE" check-config /etc/alertmanager/alertmanager.yml

echo "== go test ./internal/metrics/ =="
(cd "$ROOT" && go test ./internal/metrics/ -count=1)

echo "observability checks: OK"
