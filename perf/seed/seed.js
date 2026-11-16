// perf/seed/seed.js — issue #218 (FR5)
//
// Creates one perf tenant, three applications (web carrying the measured
// traffic, m2m for client_credentials, and a "defaults" app left at server
// defaults for the ratelimit scenario), sizes their rate-limit knobs from the
// same targets file the suite reads, and fills three disjoint user pools —
// tenant-level login users, app login users and token-holder users — plus a
// dedicated `rl` user and one user on the defaults app.
//
// Everything created carries the run id (perf-<runid>) in its name and is
// recorded in perf/.state/<runid>.json after each successful create, so a
// half-finished seed still tears down cleanly. latest.json is refreshed on
// every write so the k6 default PERF_STATE_FILE always sees a complete file.
//
// Env:
//   BASE_URL                  required; must pass the target allowlist
//   PERF_ADMIN_TOKEN          required; an issued admin JWT (15-min life —
//                             supply a fresh one per seed)
//   TARGETS_FILE              targets file for pool/quota sizing
//                             (default perf/targets.json)
//   PERF_USERS_PER_TENANT     may only RAISE the computed pool floors; a lower
//                             value or a non-number is an error
//   PERF_STATE_DIR            state directory (default perf/.state)
//   PERF_SEED_SETTLE_SECONDS  post-limits wait so server caches see them
//                             (default 65; AppLimitCacheTTL is 60s and the
//                             user-limit refresher runs every 30s)
//
// main() is dependency-injected for tests and returns an exit code; the
// process wrapper at the bottom is the only thing that calls process.exit.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkTarget, deniedDomains } from '../lib/target-guard.js';
import { loadTargets, poolFloors, appQuotas } from '../lib/targets.js';

const REFUSED_PATH = fileURLToPath(new URL('../refused-hosts.json', import.meta.url));
const DEFAULT_TARGETS_PATH = fileURLToPath(new URL('../targets.json', import.meta.url));
const DEFAULT_STATE_DIR = fileURLToPath(new URL('../.state/', import.meta.url));

const PW_CHARS = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const HEX = '0123456789abcdef';

function pad2(n) {
  return String(n).padStart(2, '0');
}

function makeRunid(now, random) {
  const hex = Array.from({ length: 6 }, () => HEX[Math.floor(random() * 16)]).join('');
  return (
    `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}` +
    `-${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}` +
    `-${hex}`
  );
}

// 24-char password; classes guaranteed by the fixed prefix. Generated per
// user, written only into the (gitignored, 0600) state file — never logged.
function genPassword(random) {
  let s = 'P9x!';
  while (s.length < 24) s += PW_CHARS[Math.floor(random() * PW_CHARS.length)];
  return s;
}

function basicAuth(app) {
  return `Basic ${Buffer.from(`${app.client_id}:${app.client_secret}`, 'utf8').toString('base64')}`;
}

function poolSize(name, floor, override) {
  if (override === undefined) return floor;
  if (override < floor) {
    throw new PoolFloorError(`PERF_USERS_PER_TENANT=${override} is below the ${name} floor of ${floor} (sized from the targets peak); unset it or raise it`);
  }
  return override;
}

class PoolFloorError extends Error {}

export async function main({ env, fetch, fs, log, now, random, sleep }) {
  const fail = (msg) => {
    log(`seed: ${msg}`);
    return 1;
  };

  // The guard runs before anything touches the network — and before the token
  // is even looked at — so a refused target can never receive a request or see
  // the credential.
  let denied;
  try {
    denied = deniedDomains(JSON.parse(fs.readFileSync(REFUSED_PATH, 'utf8')));
  } catch (e) {
    return fail('cannot read perf/refused-hosts.json — refusing to run without the deny list');
  }
  const guard = checkTarget(env.BASE_URL, denied);
  if (!guard.ok) {
    return fail(`BASE_URL refused (${guard.reason})`);
  }
  const ORIGIN = guard.origin;

  const token = env.PERF_ADMIN_TOKEN;
  if (!token) {
    return fail('PERF_ADMIN_TOKEN is not set — seed needs an issued admin JWT; see perf/README.md (15-min life)');
  }

  let targets;
  try {
    const tp = env.TARGETS_FILE || DEFAULT_TARGETS_PATH;
    targets = loadTargets(JSON.parse(fs.readFileSync(tp, 'utf8')));
  } catch (e) {
    return fail(`targets file unusable: ${e instanceof Error ? e.message : e}`);
  }

  const floors = poolFloors(targets);
  const quotas = appQuotas(targets);
  let override;
  if (env.PERF_USERS_PER_TENANT !== undefined && env.PERF_USERS_PER_TENANT !== '') {
    const n = Number(env.PERF_USERS_PER_TENANT);
    if (!Number.isInteger(n) || n < 1) {
      return fail(`PERF_USERS_PER_TENANT must be a positive integer, got ${JSON.stringify(env.PERF_USERS_PER_TENANT)}`);
    }
    override = n;
  }
  let sizes;
  try {
    sizes = {
      auth_login: poolSize('auth_login', floors.auth_login, override),
      apps_login: poolSize('apps_login', floors.apps_login, override),
      tokens: poolSize('tokens', floors.tokens, override),
    };
  } catch (e) {
    if (e instanceof PoolFloorError) return fail(e.message);
    throw e;
  }

  const runid = makeRunid(now(), random);
  const stateDir = env.PERF_STATE_DIR || DEFAULT_STATE_DIR;
  const statePath = path.join(stateDir, `${runid}.json`);
  const latestPath = path.join(stateDir, 'latest.json');

  const state = {
    version: 1,
    runid,
    base_origin: ORIGIN,
    created_at: now().toISOString(),
    tenant: null,
    apps: {},
    limits: null,
    users: { auth_login: [], apps_login: [], tokens: [], rl: null, defaults: null },
  };
  const writePrivate = (p, body) => {
    fs.writeFileSync(p, body, { mode: 0o600 });
    // writeFileSync's mode only applies on creation, and only where the FS
    // honours POSIX bits — chmod best-effort for the re-write case.
    try {
      fs.chmodSync(p, 0o600);
    } catch {
      /* platform without POSIX modes — the gitignored dir is the boundary */
    }
  };
  const persist = () => {
    fs.mkdirSync(stateDir, { recursive: true });
    const body = JSON.stringify(state, null, 2);
    writePrivate(statePath, body);
    writePrivate(latestPath, body);
  };

  // One request helper for the whole seed: redirect:manual (a 3xx is an
  // error, never a silent re-target), Retry-After honoured on 429 up to three
  // retries, and every non-2xx left for the caller to treat as fatal.
  const api = async (method, p, opts = {}) => {
    const headers = {};
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    if (opts.basic) headers.Authorization = opts.basic;
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    for (let attempt = 0; ; attempt++) {
      res = await fetch(ORIGIN + p, {
        method,
        redirect: 'manual',
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      });
      if (res.status === 429 && attempt < 3) {
        const raw = res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : null;
        const secs = Number.parseFloat(raw || '1');
        await sleep(Math.min(Number.isFinite(secs) && secs > 0 ? secs : 1, 60) * 1000);
        continue;
      }
      break;
    }
    if (res.status >= 300 && res.status < 400) {
      throw new Error(`unexpected ${res.status} redirect from ${method} ${p}`);
    }
    return res;
  };

  const auth = { token };
  try {
    // Tenant — slug-safe run id; the owner invitation lands in Mailpit on the
    // local stack.
    let res = await api('POST', '/api/v1/tenants', {
      ...auth,
      body: { name: `perf-${runid}`, slug: `perf-${runid}`, owner_email: `perf-${runid}-owner@perf.invalid` },
    });
    if (res.status !== 201) return fail(`create tenant: HTTP ${res.status}`);
    const tenant = await res.json();
    state.tenant = { id: String(tenant.id), slug: `perf-${runid}`, name: `perf-${runid}` };
    persist();
    const tid = state.tenant.id;

    // Applications — web carries traffic, m2m does client_credentials, and
    // defaults stays at server defaults for the ratelimit scenario.
    for (const [key, appType] of [['web', 'web'], ['m2m', 'm2m'], ['defaults', 'web']]) {
      res = await api('POST', `/api/v1/tenants/${tid}/applications`, {
        ...auth,
        body: { name: `perf-${runid}-${key}`, app_type: appType },
      });
      if (res.status !== 201) return fail(`create app ${key}: HTTP ${res.status}`);
      const app = await res.json();
      state.apps[key] = { id: String(app.id), client_id: app.client_id, client_secret: app.client_secret };
      persist();
    }

    // Limiter sizing on the traffic-carrying apps only — the defaults app is
    // deliberately left alone so the ratelimit scenario measures real defaults.
    res = await api('PUT', `/api/v1/tenants/${tid}/applications/${state.apps.web.id}/rate-limit`, {
      ...auth,
      body: { requests_per_minute: quotas.web.requests_per_minute, burst: quotas.web.burst, description: `perf ${runid} web quota` },
    });
    if (!(res.status >= 200 && res.status < 300)) return fail(`set web app quota: HTTP ${res.status}`);
    res = await api('PUT', `/api/v1/tenants/${tid}/applications/${state.apps.m2m.id}/rate-limit`, {
      ...auth,
      body: { requests_per_minute: quotas.m2m.requests_per_minute, burst: quotas.m2m.burst, description: `perf ${runid} m2m quota` },
    });
    if (!(res.status >= 200 && res.status < 300)) return fail(`set m2m app quota: HTTP ${res.status}`);
    res = await api('PUT', `/api/v1/tenants/${tid}/applications/${state.apps.web.id}/user-limits`, {
      ...auth,
      body: { overrides: { login: 20, register: 30, me: 600 } },
    });
    if (!(res.status >= 200 && res.status < 300)) return fail(`set web app user limits: HTTP ${res.status}`);
    state.limits = {
      web_quota: quotas.web,
      m2m_quota: quotas.m2m,
      user_overrides: { login: 20, register: 30, me: 600 },
    };
    persist();

    // Tenant-level users for /auth/login plus the ratelimit probe user.
    for (let i = 0; i < sizes.auth_login; i++) {
      const u = { email: `perf-${runid}-al${i}@perf.invalid`, password: genPassword(random) };
      res = await api('POST', `/api/v1/tenants/${tid}/users`, {
        ...auth,
        body: { email: u.email, password: u.password, first_name: 'Perf', last_name: `AL${i}` },
      });
      if (res.status !== 201) return fail(`create auth_login user ${i}: HTTP ${res.status}`);
      state.users.auth_login.push(u);
      persist();
    }
    const rl = { email: `perf-${runid}-rl@perf.invalid`, password: genPassword(random) };
    res = await api('POST', `/api/v1/tenants/${tid}/users`, {
      ...auth,
      body: { email: rl.email, password: rl.password, first_name: 'Perf', last_name: 'RL' },
    });
    if (res.status !== 201) return fail(`create rl user: HTTP ${res.status}`);
    state.users.rl = rl;
    persist();

    // App-scoped users come through apps/register on the perf web app — the
    // same surface the measured apps_login flow exercises.
    const webBasic = basicAuth(state.apps.web);
    const appUsers = async (pool, count, prefix) => {
      for (let i = 0; i < count; i++) {
        const u = { email: `perf-${runid}-${prefix}${i}@perf.invalid`, password: genPassword(random) };
        res = await api('POST', '/api/v1/auth/apps/register', {
          basic: webBasic,
          body: { email: u.email, password: u.password, first_name: 'Perf', last_name: `${prefix}${i}` },
        });
        if (res.status !== 201) return fail(`create ${prefix} user ${i}: HTTP ${res.status}`);
        pool.push(u);
        persist();
      }
      return 0;
    };
    let rc = await appUsers(state.users.apps_login, sizes.apps_login, 'ap');
    if (rc !== 0) return rc;
    rc = await appUsers(state.users.tokens, sizes.tokens, 'tk');
    if (rc !== 0) return rc;

    // One user on the defaults app for the ratelimit probes.
    const du = { email: `perf-${runid}-def@perf.invalid`, password: genPassword(random) };
    res = await api('POST', '/api/v1/auth/apps/register', {
      basic: basicAuth(state.apps.defaults),
      body: { email: du.email, password: du.password, first_name: 'Perf', last_name: 'Defaults' },
    });
    if (res.status !== 201) return fail(`create defaults user: HTTP ${res.status}`);
    state.users.defaults = du;
    persist();
  } catch (e) {
    return fail(`request failed: ${e instanceof Error ? e.message : e} — state kept at ${statePath}`);
  }

  const settleSecs = Number.parseFloat(env.PERF_SEED_SETTLE_SECONDS || '65');
  if (Number.isFinite(settleSecs) && settleSecs > 0) {
    log(
      `seed: quotas are cached up to 60s server-side (AppLimitCacheTTL) and per-user ` +
        `overrides refresh every 30s — waiting ${settleSecs}s so the run sees them`,
    );
    await sleep(settleSecs * 1000);
  }
  log(
    `seed: done — tenant ${state.tenant.slug}, pools ` +
      `auth_login=${state.users.auth_login.length} apps_login=${state.users.apps_login.length} ` +
      `tokens=${state.users.tokens.length}; state at ${statePath}`,
  );
  return 0;
}

const invokedAsMain =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (invokedAsMain) {
  main({
    env: process.env,
    fetch: globalThis.fetch,
    fs,
    log: (m) => console.log(m),
    now: () => new Date(),
    random: () => crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  }).then((code) => process.exit(code));
}
