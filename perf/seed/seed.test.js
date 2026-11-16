// perf/seed/seed.test.js — issue #218 (FR5)
//
// Seed and teardown with a fake fetch and the state directory pointed at
// os.tmpdir() — no server, no network. The assertions pin the mechanism:
// request ORDER (apps before tenant), state written after EACH create, and
// the guard/token checks running before the first request.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { main as seedMain } from './seed.js';
import { main as teardownMain } from './teardown.js';

const ADMIN_TOKEN = 'admin-jwt-TESTONLY-not-a-real-token';

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'perf-seed-test-'));
}

const MINI_TARGETS = {
  flows: Object.fromEntries(
    [
      'auth_login',
      'apps_login',
      'apps_register',
      'oauth_client_credentials',
      'oauth_refresh',
      'jwks',
      'apps_me',
    ].map((f) => [f, { rps: 0.1, max_vus: 2, p95_ms: 100, p99_ms: 200, error_rate: 0.001, placeholder: false }]),
  ),
  scenarios: {
    smoke: { iterations: 1 },
    load: { duration: '10s' },
    stress: { multiplier: 2, duration: '10s' },
    soak: { duration: '10s' },
    spike: { multiplier: 2, stages: [{ duration: '5s', target: 2 }] },
  },
};

function writeMiniTargets(dir) {
  const p = path.join(dir, 'targets.json');
  fs.writeFileSync(p, JSON.stringify(MINI_TARGETS));
  return p;
}

function okRes(status, body = {}) {
  return {
    status,
    headers: { get: () => null },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

// A fetch fake routing on the URL; `responder` may override per call.
function makeFetch(responder) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return responder(url, init, calls.length);
  };
  return { fetch, calls };
}

// Default happy-path responder for a full seed.
let appCounter = 0;
function seedResponder(url) {
  if (url.endsWith('/api/v1/tenants')) return okRes(201, { id: '42' });
  if (url.includes('/applications') && url.endsWith('/applications')) {
    appCounter += 1;
    return okRes(201, { id: String(100 + appCounter), client_id: 'cid', client_secret: 'cs' });
  }
  if (url.endsWith('/rate-limit') || url.endsWith('/user-limits')) return okRes(200, {});
  if (url.endsWith('/users')) return okRes(201, { id: '7' });
  if (url.endsWith('/auth/apps/register')) return okRes(201, { user_id: '9' });
  return okRes(500, { error: 'unrouted' });
}

function seedDeps(over = {}) {
  const dir = tmpdir();
  const logs = [];
  const env = {
    BASE_URL: 'http://localhost:9090',
    PERF_ADMIN_TOKEN: ADMIN_TOKEN,
    TARGETS_FILE: writeMiniTargets(dir),
    PERF_STATE_DIR: path.join(dir, 'state'),
    PERF_SEED_SETTLE_SECONDS: '0',
    ...over.env,
  };
  return {
    dir,
    logs,
    env,
    fetch: over.fetch,
    fs,
    log: (m) => logs.push(m),
    now: () => new Date('2026-11-16T12:00:00Z'),
    random: () => 0.5,
    sleep: async () => {},
  };
}

function readState(dir) {
  const files = fs.readdirSync(path.join(dir, 'state')).filter((f) => f.endsWith('.json') && f !== 'latest.json');
  assert.equal(files.length, 1);
  return JSON.parse(fs.readFileSync(path.join(dir, 'state', files[0]), 'utf8'));
}

// why: #218 without the admin JWT the seed must exit 1 having sent ZERO
//      requests — no create may run unauthenticated or half-recorded
test('seed: zero requests without PERF_ADMIN_TOKEN', async () => {
  const { fetch, calls } = makeFetch(seedResponder);
  const d = seedDeps({ fetch, env: { PERF_ADMIN_TOKEN: '' } });
  const code = await seedMain(d);
  assert.equal(code, 1);
  assert.equal(calls.length, 0);
});

// why: #218 a refused BASE_URL must exit before the first request — this is
//      the same guard the workflow applies to production URLs
test('seed: zero requests with a refused BASE_URL', async () => {
  const { fetch, calls } = makeFetch(seedResponder);
  const d = seedDeps({ fetch, env: { BASE_URL: 'https://auth.senie.ai' } });
  const code = await seedMain(d);
  assert.equal(code, 1);
  assert.equal(calls.length, 0);
});

// why: #218 state is written after EACH create so a half-dead seed still
//      tears down cleanly — kill the server after create #2 and exactly the
//      two created objects (tenant + first app) must be recorded
test('seed: state written after each create', async () => {
  let n = 0;
  const { fetch, calls } = makeFetch((url) => {
    n++;
    if (n > 2) return okRes(500, { error: 'server died' });
    return seedResponder(url);
  });
  const d = seedDeps({ fetch });
  const code = await seedMain(d);
  assert.equal(code, 1);
  const state = readState(d.dir);
  assert.ok(state.tenant && state.tenant.id === '42');
  assert.equal(Object.keys(state.apps).length, 1);
  assert.ok(calls.length >= 3);
});

// why: #218 PERF_USERS_PER_TENANT may only RAISE pool sizes — below the
//      computed floor the seed refuses before creating a single user
test('seed: pool below floor exits 1 with zero user creates', async () => {
  const { fetch, calls } = makeFetch(seedResponder);
  const d = seedDeps({ fetch, env: { PERF_USERS_PER_TENANT: '1' } });
  const code = await seedMain(d);
  assert.equal(code, 1);
  assert.equal(calls.length, 0);
  assert.ok(d.logs.some((m) => m.includes('floor')));
});

// why: #218 a full seed must hit the documented surfaces in order and leave a
//      complete state file for the suite — the mechanism, not just exit 0
//      (review-proofing E)
test('seed: happy path creates tenant, apps, limits, pools, state', async () => {
  const { fetch, calls } = makeFetch(seedResponder);
  const d = seedDeps({ fetch });
  const code = await seedMain(d);
  assert.equal(code, 0);
  const urls = calls.map((c) => c.url);
  assert.equal(urls[0], 'http://localhost:9090/api/v1/tenants');
  assert.equal(calls.filter((c) => c.url.includes('/applications') && c.init.method === 'POST').length, 3);
  assert.equal(calls.filter((c) => c.url.endsWith('/rate-limit')).length, 2);
  assert.equal(calls.filter((c) => c.url.endsWith('/user-limits')).length, 1);
  const state = readState(d.dir);
  assert.equal(state.tenant.slug, 'perf-20261116-120000-888888');
  assert.ok(state.users.auth_login.length >= 1);
  assert.ok(state.users.apps_login.length >= 1);
  assert.ok(state.users.tokens.length >= 1);
  assert.ok(state.users.rl && state.users.defaults);
  // every request must be redirect:manual — a 3xx must be an error, not a follow
  for (const c of calls) assert.equal(c.init.redirect, 'manual');
});

// why: #218 the admin token must never reach disk or the logs — the state
//      file holds client creds and user passwords, not the seed credential
test('seed: admin token never appears in state file or logs', async () => {
  const { fetch } = makeFetch(seedResponder);
  const d = seedDeps({ fetch });
  const code = await seedMain(d);
  assert.equal(code, 0);
  const stateDir = path.join(d.dir, 'state');
  for (const f of fs.readdirSync(stateDir)) {
    assert.equal(fs.readFileSync(path.join(stateDir, f), 'utf8').includes(ADMIN_TOKEN), false, `${f} must not contain the token`);
  }
  for (const line of d.logs) {
    assert.equal(line.includes(ADMIN_TOKEN), false);
  }
});

// why: #218 state files carry credentials — they must be written with the
//      0600 mode request. Pins the mechanism (the mode argument), not the
//      platform-dependent outcome — Windows FS ignores POSIX bits.
test('seed: state file written with mode 0600', async () => {
  const { fetch } = makeFetch(seedResponder);
  const modes = [];
  const spyFs = Object.create(fs, {
    writeFileSync: {
      value: (p, body, opts) => {
        modes.push({ p: String(p), opts });
        return fs.writeFileSync(p, body, opts);
      },
    },
  });
  const d = seedDeps({ fetch });
  d.fs = spyFs;
  await seedMain(d);
  const stateWrites = modes.filter((m) => m.p.includes('state'));
  assert.ok(stateWrites.length > 0);
  for (const w of stateWrites) {
    assert.equal(w.opts && w.opts.mode, 0o600, `state write ${w.p} must pass mode 0o600`);
  }
});

// why: #218 absent state must exit non-zero with ZERO requests — teardown
//      deletes nothing it cannot prove it owns
test('teardown: no state file -> exit 1, zero requests', async () => {
  const { fetch, calls } = makeFetch(() => okRes(500));
  const dir = tmpdir();
  const logs = [];
  const code = await teardownMain({
    env: { PERF_STATE_FILE: path.join(dir, 'nope.json'), PERF_ADMIN_TOKEN: ADMIN_TOKEN },
    fetch,
    fs,
    log: (m) => logs.push(m),
    now: () => new Date(),
  });
  assert.equal(code, 1);
  assert.equal(calls.length, 0);
});

// why: #218 malformed state must exit non-zero with ZERO requests — same
//      ownership-by-construction rule
test('teardown: malformed state -> exit 1, zero requests', async () => {
  const dir = tmpdir();
  const sp = path.join(dir, 'bad.json');
  fs.writeFileSync(sp, '{"apps":{"web":{"id":"1"}}}');
  const { fetch, calls } = makeFetch(() => okRes(500));
  const code = await teardownMain({
    env: { PERF_STATE_FILE: sp, PERF_ADMIN_TOKEN: ADMIN_TOKEN },
    fetch,
    fs,
    log: () => {},
    now: () => new Date(),
  });
  assert.equal(code, 1);
  assert.equal(calls.length, 0);
  assert.ok(fs.existsSync(sp), 'state file must be kept');
});

function writeState(dir, over = {}) {
  const state = {
    version: 1,
    runid: '20261116-120000-aaaaaa',
    base_origin: 'http://localhost:9090',
    created_at: '2026-11-16T12:00:00.000Z',
    tenant: { id: '42', slug: 'perf-x', name: 'perf-x' },
    apps: {
      web: { id: '11', client_id: 'w', client_secret: 'ws' },
      m2m: { id: '12', client_id: 'm', client_secret: 'ms' },
      defaults: { id: '13', client_id: 'd', client_secret: 'ds' },
    },
    users: { auth_login: [], apps_login: [], tokens: [], rl: null, defaults: null },
    ...over,
  };
  const sp = path.join(dir, `${state.runid}.json`);
  fs.writeFileSync(sp, JSON.stringify(state));
  return { state, sp };
}

function teardownDeps(dir, sp, fetch, logs) {
  return {
    env: { PERF_STATE_FILE: sp, PERF_ADMIN_TOKEN: ADMIN_TOKEN },
    fetch,
    fs,
    log: (m) => logs.push(m),
    now: () => new Date(),
  };
}

// why: #218 teardown must DELETE only the recorded ids, apps before tenant —
//      order and id provenance are the safety contract (review-proofing E)
test('teardown: deletes recorded app ids then tenant, in order', async () => {
  const dir = tmpdir();
  const { sp } = writeState(dir);
  const { fetch, calls } = makeFetch(() => okRes(204));
  const logs = [];
  const code = await teardownMain(teardownDeps(dir, sp, fetch, logs));
  assert.equal(code, 0);
  const dels = calls.map((c) => `${c.init.method} ${c.url}`);
  assert.deepEqual(dels, [
    'DELETE http://localhost:9090/api/v1/tenants/42/applications/11',
    'DELETE http://localhost:9090/api/v1/tenants/42/applications/12',
    'DELETE http://localhost:9090/api/v1/tenants/42/applications/13',
    'DELETE http://localhost:9090/api/v1/tenants/42',
  ]);
  for (const c of calls) assert.equal(c.init.redirect, 'manual');
  assert.equal(fs.existsSync(sp), false, 'state file removed after full teardown');
});

// why: #218 a 401/403 means the admin token died — keep the state file so a
//      retry with a fresh token can finish, and say exactly that
test('teardown: 401 keeps state file and exits 1', async () => {
  const dir = tmpdir();
  const { sp } = writeState(dir);
  const { fetch } = makeFetch(() => okRes(401));
  const logs = [];
  const code = await teardownMain(teardownDeps(dir, sp, fetch, logs));
  assert.equal(code, 1);
  assert.ok(fs.existsSync(sp));
  assert.ok(logs.some((m) => m.includes('fresh PERF_ADMIN_TOKEN')));
});

// why: #218 a 404 is reported as "not found" — never silently counted as
//      deleted by us (review-proofing I: a 404 can mean several things)
test('teardown: 404 is reported, not counted as deleted', async () => {
  const dir = tmpdir();
  const { sp } = writeState(dir);
  const { fetch } = makeFetch((url) => (url.includes('/applications/11') ? okRes(404) : okRes(204)));
  const logs = [];
  const code = await teardownMain(teardownDeps(dir, sp, fetch, logs));
  assert.equal(code, 0);
  assert.ok(logs.some((m) => m.includes('not found') && m.includes('11')));
});

// why: #218 the token must never appear in teardown logs either
test('teardown: token never appears in logs', async () => {
  const dir = tmpdir();
  const { sp } = writeState(dir);
  const { fetch } = makeFetch(() => okRes(500));
  const logs = [];
  await teardownMain(teardownDeps(dir, sp, fetch, logs));
  for (const line of logs) assert.equal(line.includes(ADMIN_TOKEN), false);
});
