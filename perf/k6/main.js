// perf/k6/main.js — issue #218
//
// The NFR scenario suite: one entry point covering
//   POST /api/v1/auth/login                 (auth_login)
//   POST /api/v1/auth/apps/login            (apps_login)
//   POST /api/v1/auth/apps/register         (apps_register)
//   POST /oauth/token client_credentials    (oauth_client_credentials)
//   POST /oauth/token refresh_token         (oauth_refresh)
//   GET  /tenants/{slug}/.well-known/jwks.json (jwks)
//   GET  /api/v1/auth/apps/me               (apps_me)
// plus `ratelimit`, a short scenario proving the default limiters still fire
// (FR4). Smoke/load/stress/soak/spike come from a targets file (FR2).
//
// Env:
//   SCENARIO         smoke|load|stress|soak|spike|ratelimit   (default smoke)
//   BASE_URL         target origin                            (default http://localhost:9090)
//   TARGETS_FILE     ABSOLUTE path; default ../targets.json relative to this file
//   PERF_STATE_FILE  ABSOLUTE path; default ../.state/latest.json (written by the seed)
//   GIT_SHA          7-40 lowercase hex commit sha — required
//   RESULTS_DIR      must start with docs/perf/ — created by the CALLER (k6
//                    does not create missing directories)
//
// Never run this against production. checkTarget refuses anything outside
// localhost/loopback/private-LAN/::1/docker-names before the first request.

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import encoding from 'k6/encoding';
import { Counter } from 'k6/metrics';
import { checkTarget, deniedDomains } from '../lib/target-guard.js';
import { loadTargets, buildOptions, placeholderFlows } from '../lib/targets.js';

// ─── Init context: validate everything before the first request ────────────

const SCENARIO = (__ENV.SCENARIO || 'smoke').toLowerCase();
const SCENARIOS = ['smoke', 'load', 'stress', 'soak', 'spike', 'ratelimit'];
if (!SCENARIOS.includes(SCENARIO)) {
  throw new Error(`SCENARIO must be one of ${SCENARIOS.join(', ')}, got ${JSON.stringify(SCENARIO)}`);
}

const denied = deniedDomains(JSON.parse(open('../refused-hosts.json')));
const guard = checkTarget(__ENV.BASE_URL || 'http://localhost:9090', denied);
if (!guard.ok) {
  throw new Error(`perf target refused: ${guard.reason}${guard.host !== undefined ? ` (${guard.host})` : ''}`);
}
const ORIGIN = guard.origin; // callers build every URL from this, never the raw env
const TARGET_HOST = guard.host;

const GIT_SHA = __ENV.GIT_SHA || '';
if (!/^[0-9a-f]{7,40}$/.test(GIT_SHA)) {
  throw new Error('GIT_SHA must be a 7-40 char lowercase hex commit sha');
}

const RESULTS_DIR = __ENV.RESULTS_DIR || '';
if (!RESULTS_DIR.startsWith('docs/perf/')) {
  throw new Error('RESULTS_DIR must start with docs/perf/ (the perf results tree)');
}

const STARTED_AT = new Date().toISOString();

function isAbsPath(p) {
  return /^([A-Za-z]:[\\/]|\/)/.test(p);
}
function baseName(p) {
  const s = String(p).replace(/\\/g, '/');
  return s.slice(s.lastIndexOf('/') + 1);
}

// Targets file — required for every scenario except ratelimit, which measures
// the server's compiled-in defaults and takes no targets.
let TARGETS = null;
let targetsFileName = '(none — ratelimit)';
if (SCENARIO !== 'ratelimit') {
  const tf = __ENV.TARGETS_FILE;
  let raw;
  if (tf === undefined || tf === '') {
    raw = open('../targets.json');
    targetsFileName = 'targets.json';
  } else {
    if (!isAbsPath(tf)) {
      throw new Error('TARGETS_FILE must be an absolute path (open() resolves relative paths against this file, not your cwd)');
    }
    targetsFileName = baseName(tf);
    raw = open(tf);
  }
  TARGETS = loadTargets(JSON.parse(raw));
  const ph = placeholderFlows(TARGETS);
  if (ph.length > 0) {
    console.log(`NOTE: placeholder thresholds in use for: ${ph.join(', ')} — numbers are unagreed until the NFR table lands (#170)`);
  }
}

// Fixture state written by perf/seed/seed.js.
let stateRaw;
const sf = __ENV.PERF_STATE_FILE;
if (sf === undefined || sf === '') {
  try {
    stateRaw = open('../.state/latest.json');
  } catch (e) {
    throw new Error('no PERF_STATE_FILE given and perf/.state/latest.json is missing — run the seed first (node perf/seed/seed.js)');
  }
} else {
  if (!isAbsPath(sf)) {
    throw new Error('PERF_STATE_FILE must be an absolute path (open() resolves relative paths against this file, not your cwd)');
  }
  stateRaw = open(sf);
}
const STATE = JSON.parse(stateRaw);

function needState(cond, what) {
  if (!cond) throw new Error(`perf state file unusable: missing ${what}`);
}
needState(STATE && typeof STATE === 'object', 'top-level object');
needState(typeof STATE.runid === 'string' && STATE.runid.length > 0, 'runid');
needState(STATE.tenant && typeof STATE.tenant.slug === 'string', 'tenant.slug');
for (const a of ['web', 'm2m', 'defaults']) {
  needState(STATE.apps && STATE.apps[a] && STATE.apps[a].client_id && STATE.apps[a].client_secret, `apps.${a} credentials`);
}
needState(Array.isArray(STATE.users && STATE.users.auth_login) && STATE.users.auth_login.length > 0, 'users.auth_login pool');
needState(Array.isArray(STATE.users && STATE.users.apps_login) && STATE.users.apps_login.length > 0, 'users.apps_login pool');
needState(Array.isArray(STATE.users && STATE.users.tokens) && STATE.users.tokens.length > 0, 'users.tokens pool');
needState(STATE.users && STATE.users.rl && STATE.users.rl.email, 'users.rl');
needState(STATE.users && STATE.users.defaults && STATE.users.defaults.email, 'users.defaults');

// ─── Options ────────────────────────────────────────────────────────────────

const limiterFired = new Counter('limiter_fired');

function ratelimitOptions() {
  return {
    scenarios: {
      ratelimit: { executor: 'per-vu-iterations', exec: 'ratelimit', vus: 1, iterations: 1, maxDuration: '5m' },
    },
    thresholds: {
      // All three probes must see a 429, and every limiter_fired check must pass.
      limiter_fired: ['count>=3'],
      'checks{check:limiter_fired}': ['rate==1'],
    },
    maxRedirects: 0,
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  };
}

export const options = SCENARIO === 'ratelimit' ? ratelimitOptions() : buildOptions(TARGETS, SCENARIO);

// ─── Shared helpers ─────────────────────────────────────────────────────────

const FLOW_INDEX = {
  auth_login: 0,
  apps_login: 1,
  apps_register: 2,
  oauth_client_credentials: 3,
  oauth_refresh: 4,
  jwks: 5,
  apps_me: 6,
  setup: 7,
};

// One X-Forwarded-For per iteration. Every limiter in the measured path keys
// on c.RealIP(), and a VU doing far more than 5 logins/min would trip the
// login_ip bucket long before the scenario rate is reached — per-VU XFF is
// not enough, per-iteration is. 24 bits of spread: flow index in the high
// bits, the scenario's iteration counter in the low 20.
//
// This only works because the perf compose overlay sets TRUSTED_PROXIES for
// the address k6's traffic arrives from; without the overlay the header is
// ignored (harmless — the run is then simply wrong, not silently different).
// Keep ALL XFF logic in this one helper so it can be dropped with the overlay.
function xff(flow) {
  const n = (((FLOW_INDEX[flow] || 0) << 20) | (exec.scenario.iterationInTest & 0xfffff)) >>> 0;
  return `10.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

function reqParams(flow, expectStatus, headers) {
  return {
    headers: Object.assign({ 'X-Forwarded-For': xff(flow) }, headers),
    tags: { flow },
    responseCallback: http.expectedStatuses(expectStatus),
    // A redirect must count as a failure, never a silent re-target.
    redirects: 0,
    timeout: '30s',
  };
}

function basicAuthHeader(app) {
  return `Basic ${encoding.b64encode(`${app.client_id}:${app.client_secret}`)}`;
}

function formBody(fields) {
  return Object.keys(fields)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(fields[k])}`)
    .join('&');
}

function safeJson(r) {
  try {
    return r.json();
  } catch (e) {
    return null;
  }
}

function pickUser(pool, iter) {
  return pool[iter % pool.length];
}

// Retry-After may arrive under either canonicalisation.
function hasRetryAfter(res) {
  return res.headers['Retry-After'] !== undefined || res.headers['retry-after'] !== undefined;
}

// ─── The seven flows ────────────────────────────────────────────────────────

export function auth_login() {
  const u = pickUser(STATE.users.auth_login, exec.scenario.iterationInTest);
  const res = http.post(
    `${ORIGIN}/api/v1/auth/login`,
    JSON.stringify({ email: u.email, password: u.password }),
    reqParams('auth_login', 200, { 'Content-Type': 'application/json' }),
  );
  // A 200 can be an OTP challenge — only access_token proves a full login.
  check(res, { 'auth_login: access_token': (r) => { const j = safeJson(r); return !!j && !!j.access_token; } });
}

export function apps_login() {
  const u = pickUser(STATE.users.apps_login, exec.scenario.iterationInTest);
  const res = http.post(
    `${ORIGIN}/api/v1/auth/apps/login`,
    JSON.stringify({ email: u.email, password: u.password }),
    reqParams('apps_login', 200, {
      'Content-Type': 'application/json',
      Authorization: basicAuthHeader(STATE.apps.web),
    }),
  );
  check(res, { 'apps_login: access_token': (r) => { const j = safeJson(r); return !!j && !!j.access_token; } });
}

// The seed's runid is shared by every k6 run against that seed, and
// iterationInTest/idInTest restart at 0/1 each run — so a second run would
// re-register the same addresses and take 409s. A per-VU stamp from init time
// keeps addresses unique across runs; iterationInTest keeps them unique
// within one.
const REGISTER_STAMP = `${Date.now().toString(36)}${Math.floor(Math.random() * 1679616).toString(36)}`;

export function apps_register() {
  const iter = exec.scenario.iterationInTest;
  const vu = exec.vu.idInTest;
  const email = `perf-${STATE.runid}-r${REGISTER_STAMP}-${vu}-${iter}@perf.invalid`;
  const password = `P3rf${iter.toString(36)}x${vu.toString(36)}yZ9`;
  const res = http.post(
    `${ORIGIN}/api/v1/auth/apps/register`,
    JSON.stringify({ email, password, first_name: 'Perf', last_name: 'Load' }),
    reqParams('apps_register', 201, {
      'Content-Type': 'application/json',
      Authorization: basicAuthHeader(STATE.apps.web),
    }),
  );
  check(res, { 'apps_register: account created': (r) => {
    const j = safeJson(r);
    return !!j && !!(j.user_id || j.id || j.email);
  } });
}

export function oauth_client_credentials() {
  const res = http.post(
    `${ORIGIN}/oauth/token`,
    formBody({ grant_type: 'client_credentials' }),
    reqParams('oauth_client_credentials', 200, {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuthHeader(STATE.apps.m2m),
    }),
  );
  check(res, { 'oauth_client_credentials: access_token': (r) => { const j = safeJson(r); return !!j && !!j.access_token; } });
}

export function jwks() {
  const res = http.get(
    `${ORIGIN}/tenants/${STATE.tenant.slug}/.well-known/jwks.json`,
    reqParams('jwks', 200, {}),
  );
  check(res, { 'jwks: keys array': (r) => { const j = safeJson(r); return !!j && Array.isArray(j.keys); } });
}

// ─── Token-holder flows ─────────────────────────────────────────────────────
// Refresh tokens are single-use and replay REVOKES the whole session family,
// so a holder pair is only ever sent once and discarded on any failure.
// Module-level state is per-VU in k6; keyed per flow in case one VU serves
// both token-holder scenarios.

const holder = { oauth_refresh: null, apps_me: null };

function tokenUser() {
  const pool = STATE.users.tokens;
  return pool[(exec.vu.idInTest - 1) % pool.length];
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// Apps login for holder setup — tagged flow:setup so it never pollutes the
// measured flows' thresholds.
function loginAppUser(u) {
  const res = http.post(
    `${ORIGIN}/api/v1/auth/apps/login`,
    JSON.stringify({ email: u.email, password: u.password }),
    reqParams('setup', 200, {
      'Content-Type': 'application/json',
      Authorization: basicAuthHeader(STATE.apps.web),
    }),
  );
  const j = res.status === 200 ? safeJson(res) : null;
  if (!j || !j.access_token || !j.refresh_token) return null;
  return {
    access: j.access_token,
    refresh: j.refresh_token,
    expiresAt: typeof j.expires_at === 'number' ? j.expires_at : nowSeconds() + (j.expires_in || 900),
  };
}

// Refresh grant — returns the rotated pair or null. Only ever called with the
// most recently issued token.
function refreshPair(current) {
  const res = http.post(
    `${ORIGIN}/oauth/token`,
    formBody({ grant_type: 'refresh_token', refresh_token: current.refresh }),
    reqParams('setup', 200, {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuthHeader(STATE.apps.web),
    }),
  );
  const j = res.status === 200 ? safeJson(res) : null;
  if (!j || !j.access_token || !j.refresh_token) return null;
  return { access: j.access_token, refresh: j.refresh_token, expiresAt: nowSeconds() + (j.expires_in || 900) };
}

export function oauth_refresh() {
  if (!holder.oauth_refresh) {
    holder.oauth_refresh = loginAppUser(tokenUser());
  }
  const h = holder.oauth_refresh;
  if (!h) {
    // Setup failed, so no measured request goes out. Record it as a failed
    // check: checks{flow:oauth_refresh} is thresholded, so lost iterations
    // cannot quietly thin the flow while its other gates stay green.
    check(null, { 'oauth_refresh: holder login': () => false });
    return;
  }
  const res = http.post(
    `${ORIGIN}/oauth/token`,
    formBody({ grant_type: 'refresh_token', refresh_token: h.refresh }),
    reqParams('oauth_refresh', 200, {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuthHeader(STATE.apps.web),
    }),
  );
  const j = res.status === 200 ? safeJson(res) : null;
  if (j && j.access_token && j.refresh_token) {
    holder.oauth_refresh = { access: j.access_token, refresh: j.refresh_token, expiresAt: nowSeconds() + (j.expires_in || 900) };
  } else {
    // ANY failure — 4xx, 5xx, timeout — means the pair is suspect. Discard it;
    // resending a used refresh token revokes the session family.
    holder.oauth_refresh = null;
  }
  check(res, { 'oauth_refresh: rotated pair': (r) => r.status === 200 && !!j && !!j.access_token });
}

export function apps_me() {
  let h = holder.apps_me;
  // Access tokens live 15 minutes; renew through the refresh grant a minute
  // early so /me traffic never carries an expired token.
  if (h && nowSeconds() >= h.expiresAt - 60) {
    h = refreshPair(h);
  }
  if (!h) {
    h = loginAppUser(tokenUser());
  }
  holder.apps_me = h;
  if (!h) {
    // Same as oauth_refresh: a holder that cannot log in is a failed check.
    check(null, { 'apps_me: holder login': () => false });
    return;
  }
  const res = http.get(
    `${ORIGIN}/api/v1/auth/apps/me`,
    reqParams('apps_me', 200, {
      Authorization: `Bearer ${h.access}`,
      'X-Client-Authorization': basicAuthHeader(STATE.apps.web),
    }),
  );
  if (res.status !== 200) {
    holder.apps_me = null; // dead pair — re-authenticate next iteration
  }
  check(res, { 'apps_me: user payload': (r) => { const j = safeJson(r); return !!j && !!(j.id || j.user_id || j.email); } });
}

// ─── ratelimit scenario (FR4) ───────────────────────────────────────────────
// Runs against the plain stack: NO X-Forwarded-For, the point is the DEFAULT
// buckets firing. Redis keeps the buckets hot up to 60s across restarts — a
// stale bucket fails the first-request check with a "wait 60 s" hint rather
// than a silent pass.

function probeAuthLoginIP() {
  const u = STATE.users.rl;
  const params = {
    headers: { 'Content-Type': 'application/json' },
    tags: { flow: 'auth_login_default' },
    responseCallback: http.expectedStatuses(200, 429),
    redirects: 0,
    timeout: '30s',
  };
  let fired = false;
  for (let i = 0; i < 6; i++) {
    const res = http.post(
      `${ORIGIN}/api/v1/auth/login`,
      JSON.stringify({ email: u.email, password: u.password }),
      params,
    );
    if (i === 0) {
      const j = safeJson(res);
      if (!(res.status === 200 && j && j.access_token)) {
        console.error('ratelimit: first /auth/login was not 200+access_token — bucket not fresh: wait 60 s');
        return false;
      }
    } else if (res.status === 429 && hasRetryAfter(res)) {
      fired = true;
    }
  }
  return fired;
}

function limiterOf(res) {
  const j = safeJson(res);
  return j && typeof j.limiter === 'string' ? j.limiter : '';
}

// Probes (ii) and (iii) share one source IP. Each must show its own limiter:
// the first request has to reach authentication (401), and the 429 that counts
// has to name the limiter under test in its body. Otherwise an IP bucket left
// empty by the other probe would pass this one with the limiter switched off.
function probeAppUnverifiedIP() {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${encoding.b64encode(`${STATE.apps.defaults.client_id}:wrong-secret`)}`,
    },
    tags: { flow: 'apps_login_default' },
    responseCallback: http.expectedStatuses(401, 429),
    redirects: 0,
    timeout: '30s',
  };
  // Any password works here — the client secret is what fails to verify.
  const body = JSON.stringify({ email: STATE.users.defaults.email, password: 'x'.repeat(9) });
  let fired = false;
  for (let i = 0; i < 6; i++) {
    const res = http.post(`${ORIGIN}/api/v1/auth/apps/login`, body, params);
    if (i === 0) {
      if (res.status !== 401) {
        console.error(`ratelimit: first wrong-secret request was ${res.status}, not 401 — IP bucket not fresh: wait 60 s`);
        return false;
      }
    } else if (res.status === 429 && hasRetryAfter(res) && limiterOf(res) === 'ip') {
      fired = true;
    }
  }
  return fired;
}

function probeAppUserLogin() {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: basicAuthHeader(STATE.apps.defaults),
    },
    tags: { flow: 'apps_login_default' },
    responseCallback: http.expectedStatuses(401, 429),
    redirects: 0,
    timeout: '30s',
  };
  const body = JSON.stringify({ email: STATE.users.defaults.email, password: 'y'.repeat(9) });
  let fired = false;
  for (let i = 0; i < 6; i++) {
    const res = http.post(`${ORIGIN}/api/v1/auth/apps/login`, body, params);
    if (i === 0) {
      if (res.status !== 401) {
        console.error(`ratelimit: first wrong-password request was ${res.status}, not 401 — user bucket not fresh: wait 60 s`);
        return false;
      }
    } else if (res.status === 429 && hasRetryAfter(res) && limiterOf(res) === 'user') {
      fired = true;
    }
  }
  return fired;
}

export function ratelimit() {
  // The per-user probe runs before the wrong-secret probe: the wrong secrets
  // fill this IP's bad-credential bucket, which would answer the user probe
  // with an IP 429 before the user limiter is reached.
  const probes = [probeAuthLoginIP(), probeAppUserLogin(), probeAppUnverifiedIP()];
  for (const fired of probes) {
    limiterFired.add(fired ? 1 : 0);
    check(null, { limiter_fired: () => fired });
  }
}

// ─── Reporting (FR6) ────────────────────────────────────────────────────────

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// k6 summary threshold entries have been both bare booleans and {ok: bool};
// read either.
function thresholdOk(v) {
  if (typeof v === 'boolean') return v;
  if (v && typeof v === 'object' && typeof v.ok === 'boolean') return v.ok;
  return true;
}

function metricRows(data) {
  const rows = [];
  const names = Object.keys(data.metrics || {}).sort();
  for (const name of names) {
    const m = data.metrics[name];
    const vals = m.values || {};
    const cells = ['avg', 'min', 'med', 'max', 'p(95)', 'p(99)', 'rate', 'count', 'passes', 'fails']
      .filter((k) => vals[k] !== undefined)
      .map((k) => `<td>${esc(k)}</td><td>${esc(typeof vals[k] === 'number' ? +vals[k].toFixed(4) : vals[k])}</td>`)
      .join('');
    const th = m.thresholds
      ? Object.entries(m.thresholds)
          .map(([expr, v]) => `<span class="${thresholdOk(v) ? 'ok' : 'bad'}">${esc(expr)} ${thresholdOk(v) ? 'ok' : 'FAILED'}</span>`)
          .join(' ')
      : '';
    rows.push(`<tr><td class="name">${esc(name)}${th ? `<br>${th}` : ''}</td><td>${esc(m.type || '')}</td><td>${cells}</td></tr>`);
  }
  return rows.join('\n');
}

function renderReport(data) {
  const ph = TARGETS ? placeholderFlows(TARGETS) : [];
  const breached = [];
  for (const [name, m] of Object.entries(data.metrics || {})) {
    if (!m.thresholds) continue;
    for (const [expr, v] of Object.entries(m.thresholds)) {
      if (!thresholdOk(v)) breached.push(`${name}: ${expr}`);
    }
  }
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>perf ${esc(SCENARIO)} — ${esc(GIT_SHA.slice(0, 7))}</title>
<style>
body{font-family:ui-monospace,Menlo,Consolas,monospace;margin:2rem;color:#1a1a1a}
table{border-collapse:collapse;width:100%;font-size:.85rem}
td,th{border:1px solid #ccc;padding:.3rem .5rem;vertical-align:top;text-align:left}
.name{max-width:34rem;word-break:break-all}
.ok{color:#137333}.bad{color:#c5221f;font-weight:700}
.meta{color:#555}.banner{background:#fff3cd;border:1px solid #e0a800;padding:.6rem .8rem;margin:1rem 0}
.fail{background:#f8d7da;border:1px solid #c5221f;padding:.6rem .8rem;margin:1rem 0}
</style></head><body>
<h1>emc-auth-server perf — ${esc(SCENARIO)}</h1>
<p class="meta">commit ${esc(GIT_SHA)} · target ${esc(TARGET_HOST)} · scenario ${esc(SCENARIO)} ·
started ${esc(STARTED_AT)} · targets file ${esc(targetsFileName)}</p>
${ph.length ? `<p class="banner">Placeholder thresholds in use for: ${esc(ph.join(', '))} — these numbers are unagreed until the NFR table lands (#170).</p>` : ''}
${breached.length ? `<p class="fail">Thresholds breached:<br>${breached.map(esc).join('<br>')}</p>` : ''}
<table><tr><th>metric</th><th>type</th><th>values</th></tr>
${metricRows(data)}
</table>
</body></html>
`;
}

function textReport(data) {
  const breached = [];
  for (const [name, m] of Object.entries(data.metrics || {})) {
    if (!m.thresholds) continue;
    for (const [expr, v] of Object.entries(m.thresholds)) {
      if (!thresholdOk(v)) breached.push(`  ${name} :: ${expr}`);
    }
  }
  const lines = [`perf ${SCENARIO} @ ${TARGET_HOST} — ${GIT_SHA.slice(0, 7)} — results in ${RESULTS_DIR}`];
  if (breached.length) {
    lines.push('thresholds breached:');
    lines.push(...breached);
  } else {
    lines.push('all thresholds held');
  }
  return `${lines.join('\n')}\n`;
}

export function handleSummary(data) {
  const meta = {
    git_sha: GIT_SHA,
    scenario: SCENARIO,
    targets_file: targetsFileName,
    base_url: TARGET_HOST,
    placeholder_flows: TARGETS ? placeholderFlows(TARGETS) : [],
    started_at: STARTED_AT,
  };
  const out = {};
  out[`${RESULTS_DIR}/summary.json`] = JSON.stringify(data, null, 2);
  out[`${RESULTS_DIR}/meta.json`] = `${JSON.stringify(meta, null, 2)}\n`;
  out[`${RESULTS_DIR}/report.html`] = renderReport(data);
  out.stdout = textReport(data);
  return out;
}
