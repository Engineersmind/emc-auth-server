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
//   - http_req_failed < 1% (429s from rate limiter are NOT failures — they are expected)
//   - Zero HTTP 5xx responses
//
// Note: the login rate limiter (5 req/min/IP) will produce 429s at load.
// k6 virtual users share the test runner IP, so 429s are expected beyond 5 VUs.
// The check allows 429 as a passing status. Only 5xx is a failure.

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TENANT   = __ENV.TENANT   || 'emc';
const EMAIL    = __ENV.EMAIL    || 'admin@emc.local';
const PASSWORD = __ENV.PASSWORD || 'ChangeMe123!';

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '60s', target: 500 },
    { duration: '20s', target: 0 },
  ],
  thresholds: {
    // p99 latency ≤ 200ms on login (NFR-02)
    'http_req_duration{name:login}': ['p(99)<200'],
    // zero HTTP 5xx errors (system stability)
    'http_req_failed': ['rate<0.01'],
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

  check(res, {
    'status is 200 or 429': (r) => r.status === 200 || r.status === 429,
    'not 5xx': (r) => r.status < 500,
  });

  // No sleep — we want maximum throughput to stress the server.
  // The rate limiter will produce 429s at high VU counts (expected).
}
