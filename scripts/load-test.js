// EMC Auth Server — k6 Load Test
//
// Prerequisites:
//   - k6 installed: https://k6.io/docs/getting-started/installation/
//   - Server running with seeded data (make up-d)
//
// Run against local server:
//   k6 run scripts/load-test.js
//
// Run against custom target:
//   BASE_URL=https://auth.example.com k6 run scripts/load-test.js
//
// Expected results at 500 VUs:
//   - p99 latency ≤ 200ms (NFR-02)
//   - Zero HTTP 5xx responses (system stability)
//   - 429s from rate limiter are expected and do NOT count as failures
//
// Note: the login rate limiter (5 req/min/IP) will produce 429s at load.
// k6 virtual users share the test runner IP, so 429s are expected beyond 5 VUs.
// Only HTTP 5xx responses constitute a test failure.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TENANT   = __ENV.TENANT   || 'emc';
const EMAIL    = __ENV.EMAIL    || 'admin@emc.local';
// NOTE: Override PASSWORD when running against staging/production environments.
// This default matches the dev seed (SEED_ADMIN_PASSWORD).
const PASSWORD = __ENV.PASSWORD || 'ChangeMe123!';

// Custom counter for HTTP 5xx responses only.
// http_req_failed (built-in) counts all 4xx as failures, which causes the
// threshold to trip spuriously at 500 VUs because the rate limiter produces
// a large volume of expected 429s. We track 5xx separately (H-03 fix).
const serverErrors = new Counter('server_errors');

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '60s', target: 500 },
    { duration: '20s', target: 0 },
  ],
  thresholds: {
    // p99 latency ≤ 200ms on login (NFR-02)
    'http_req_duration{name:login}': ['p(99)<200'],
    // Zero HTTP 5xx responses allowed (system stability).
    // 429s are expected under rate limiter pressure and are NOT counted here.
    'server_errors': ['count<1'],
  },
};

export default function () {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Slug': TENANT,
      },
      tags: { name: 'login' },
    }
  );

  // Count 5xx as hard failures; 429 is an expected rate-limit response.
  if (res.status >= 500) {
    serverErrors.add(1);
  }

  check(res, {
    'status is 200 or 429': (r) => r.status === 200 || r.status === 429,
    'not 5xx': (r) => r.status < 500,
  });

  // No sleep — we want maximum throughput to stress the server.
  // The rate limiter will produce 429s at high VU counts (expected).
}
