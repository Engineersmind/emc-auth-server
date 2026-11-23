// perf/lib/targets.test.js — issue #218 (FR2)
//
// Validation must throw on every malformed shape — a silently accepted config
// would run the suite against thresholds nobody chose.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  FLOWS,
  loadTargets,
  buildOptions,
  placeholderFlows,
  peakFactor,
  poolFloors,
  appQuotas,
} from './targets.js';

function base() {
  const flows = {};
  for (const f of FLOWS) {
    flows[f] = { rps: 2, max_vus: 4, p95_ms: 100, p99_ms: 200, error_rate: 0.001, placeholder: false };
  }
  return {
    flows,
    scenarios: {
      smoke: { iterations: 2 },
      load: { duration: '1m' },
      stress: { multiplier: 2, duration: '1m' },
      soak: { duration: '2m' },
      spike: { multiplier: 4, stages: [{ duration: '10s', target: 4 }] },
    },
  };
}

function expectThrow(t, mutate, re = /targets:/) {
  const t2 = base();
  mutate(t2);
  assert.throws(() => loadTargets(t2), re);
}

// why: #218 a flow missing from the file must refuse the run, not skip it
test('missing flow throws', () => expectThrow(base(), (t) => delete t.flows.jwks));

// why: #218 a typo'd flow name must refuse, not be silently ignored
test('unknown flow throws', () => expectThrow(base(), (t) => { t.flows.bogus = t.flows.jwks; }));

// why: #218 a flow missing a field must refuse — p99 cannot be assumed
test('missing flow field throws', () => expectThrow(base(), (t) => delete t.flows.jwks.p99_ms));

// why: #218 an unrecognised field inside a flow is a typo — refuse it
test('unknown flow key throws', () => expectThrow(base(), (t) => { t.flows.jwks.latency = 5; }));

// why: #218 rps must be a positive number
test('rps zero throws', () => expectThrow(base(), (t) => { t.flows.jwks.rps = 0; }));
test('rps non-number throws', () => expectThrow(base(), (t) => { t.flows.jwks.rps = 'fast'; }));

// why: #218 max_vus must be a positive integer (drives executor sizing)
test('max_vus fraction throws', () => expectThrow(base(), (t) => { t.flows.jwks.max_vus = 1.5; }));
test('max_vus zero throws', () => expectThrow(base(), (t) => { t.flows.jwks.max_vus = 0; }));

// why: #218 latency budgets must be positive and ordered
test('p95_ms zero throws', () => expectThrow(base(), (t) => { t.flows.jwks.p95_ms = 0; }));
test('p99 below p95 throws', () => expectThrow(base(), (t) => { t.flows.jwks.p99_ms = 50; }));

// why: #218 error_rate must be a probability
test('error_rate above 1 throws', () => expectThrow(base(), (t) => { t.flows.jwks.error_rate = 1.5; }));
test('error_rate negative throws', () => expectThrow(base(), (t) => { t.flows.jwks.error_rate = -0.1; }));

// why: #218 placeholder must be boolean so the banner cannot be forged off
test('placeholder non-boolean throws', () => expectThrow(base(), (t) => { t.flows.jwks.placeholder = 'yes'; }));

// why: #218 all five scenarios must be defined
test('missing scenario throws', () => expectThrow(base(), (t) => delete t.scenarios.soak));

// why: #218 an unrecognised scenario key is a typo — refuse it
test('unknown scenario throws', () => expectThrow(base(), (t) => { t.scenarios.flood = { duration: '1m' }; }));

// why: #218 smoke needs a positive iteration count
test('smoke iterations bad throws', () => expectThrow(base(), (t) => { t.scenarios.smoke.iterations = 0; }));

// why: #218 a duration k6 cannot parse must be caught here, not mid-run
test('bad duration throws', () => expectThrow(base(), (t) => { t.scenarios.load.duration = 'a while'; }));

// why: #218 spike needs stages and each stage a positive target multiplier
test('empty spike stages throws', () => expectThrow(base(), (t) => { t.scenarios.spike.stages = []; }));
test('spike stage without target throws', () =>
  expectThrow(base(), (t) => { t.scenarios.spike.stages = [{ duration: '10s' }]; }));

// why: #218 stress without a multiplier defaults to 2x (issue text), not an error
test('stress multiplier defaults to 2', () => {
  const t = base();
  delete t.scenarios.stress.multiplier;
  loadTargets(t);
  const o = buildOptions(t, 'stress');
  assert.equal(o.scenarios.auth_login.rate, 4);
});

// why: #218 threshold strings must be exact — k6 parses them verbatim (FR2)
test('exact threshold strings for one flow', () => {
  const o = buildOptions(base(), 'load');
  assert.deepEqual(o.thresholds['http_req_duration{flow:auth_login}'], ['p(95)<100', 'p(99)<200']);
  assert.deepEqual(o.thresholds['http_req_failed{flow:auth_login}'], ['rate<=0.001']);
  // why: #218 a zero-sample flow must not pass — count>=1 pins that (F12)
  assert.deepEqual(o.thresholds['http_reqs{flow:auth_login}'], ['count>=1']);
  // why: #218 a 200 OTP challenge without access_token passes http_req_failed;
  //      only the body check catches it, so checks must carry the error budget
  assert.deepEqual(o.thresholds['checks{flow:auth_login}'], ['rate>=0.999']);
  // why: #218 the RPS half of "VUs/RPS" is dropped_iterations on arrival-rate
  //      executors (F12)
  assert.deepEqual(o.thresholds['dropped_iterations{scenario:auth_login}'], ['count==0']);
});

// why: #218 smoke uses per-vu-iterations, not an arrival-rate executor, so
//      the dropped-iterations threshold must not appear there
test('smoke has no dropped_iterations threshold', () => {
  const o = buildOptions(base(), 'smoke');
  assert.equal(Object.keys(o.thresholds).some((k) => k.startsWith('dropped_iterations')), false);
  assert.equal(o.scenarios.jwks.executor, 'per-vu-iterations');
  assert.equal(o.scenarios.jwks.vus, 1);
});

// why: #218 stress is defined as 2x target — assert the mechanism, not the
//      symptom: the executor rate itself is doubled (review-proofing E)
test('stress rate is 2x the flow rps', () => {
  const o = buildOptions(base(), 'stress');
  assert.equal(o.scenarios.jwks.executor, 'constant-arrival-rate');
  assert.equal(o.scenarios.jwks.rate, 4);
  assert.equal(o.scenarios.jwks.maxVUs, 8);
});

// why: #218 spike stages multiply the flow rps per stage
test('spike stages multiply rps', () => {
  const o = buildOptions(base(), 'spike');
  assert.equal(o.scenarios.jwks.executor, 'ramping-arrival-rate');
  assert.deepEqual(o.scenarios.jwks.stages, [{ duration: '10s', target: 8 }]);
});

// why: #218 maxRedirects 0 means a 3xx counts as failure — nothing may pull
//      the run off its allowlisted origin
test('maxRedirects is 0', () => {
  assert.equal(buildOptions(base(), 'load').maxRedirects, 0);
});

// why: #218 the fail-demo file must produce p(95)<0.001 — the acceptance test
//      that a breached threshold fails the run depends on this exact string
test('fail-demo targets yield p(95)<0.001', () => {
  const t = loadTargets(readFileSync(new URL('../targets.fail-demo.json', import.meta.url), 'utf8'));
  const o = buildOptions(t, 'load');
  assert.equal(o.thresholds['http_req_duration{flow:apps_me}'][0], 'p(95)<0.001');
});

// why: #218 the shipped targets.json must load and cover all 7 flows — it is
//      the file the suite runs when TARGETS_FILE is unset
test('real perf/targets.json loads, all placeholder, jwks error_rate 0', () => {
  const t = loadTargets(readFileSync(new URL('../targets.json', import.meta.url), 'utf8'));
  for (const f of FLOWS) assert.ok(t.flows[f], `flow ${f} present`);
  assert.equal(placeholderFlows(t).length, FLOWS.length);
  assert.equal(t.flows.jwks.error_rate, 0);
  for (const s of ['smoke', 'load', 'stress', 'soak', 'spike']) {
    assert.ok(t.scenarios[s], `scenario ${s} present`);
    assert.doesNotThrow(() => buildOptions(t, s));
  }
});

// why: #218 the local file the reviewer runs must also validate for all flows
test('targets.local.json loads and covers all flows', () => {
  const t = loadTargets(readFileSync(new URL('../targets.local.json', import.meta.url), 'utf8'));
  for (const f of FLOWS) assert.ok(t.flows[f]);
  assert.equal(placeholderFlows(t).length, 0);
  assert.doesNotThrow(() => buildOptions(t, 'smoke'));
});

// why: #218 sizing must track the configured peak, not a hardcoded one —
//      poolFloors/appQuotas are what keep the suite under the limiters (FR4)
test('poolFloors and appQuotas scale with the peak multiplier', () => {
  const t = base(); // P = max(2, 4) = 4
  assert.equal(peakFactor(t), 4);
  const floors = poolFloors(t);
  assert.equal(floors.auth_login, Math.ceil((2 * 4 * 60) / 10) + 1);
  assert.equal(floors.apps_login, Math.ceil((2 * 4 * 60) / 20) + 1);
  const q = appQuotas(t);
  // web quota covers login+register+me+refresh rps at peak, plus 20%
  assert.equal(q.web.requests_per_minute, Math.ceil((2 + 2 + 2 + 2) * 4 * 60 * 1.2));
  assert.equal(q.web.burst, q.web.requests_per_minute);
  assert.equal(q.m2m.requests_per_minute, Math.ceil(2 * 4 * 60 * 1.2));
});

// why: #218 an error_rate of 0 must demand every check pass (rate>=1), and the
//      floor must not carry float noise k6 would parse verbatim
test('checks threshold tracks error_rate exactly', () => {
  const o = buildOptions(base(), 'smoke');
  for (const f of FLOWS) {
    const e = base().flows[f].error_rate;
    assert.deepEqual(o.thresholds[`checks{flow:${f}}`], [`rate>=${Number((1 - e).toFixed(6))}`]);
  }
  const t = base();
  t.flows.jwks.error_rate = 0;
  assert.deepEqual(buildOptions(t, 'load').thresholds['checks{flow:jwks}'], ['rate>=1']);
  t.flows.jwks.error_rate = 0.003;
  assert.deepEqual(buildOptions(t, 'load').thresholds['checks{flow:jwks}'], ['rate>=0.997']);
});

// why: #218 k6 arrival-rate executors need an integer rate per timeUnit — a
//      fractional rps (0.5) or multiplier (1.5x on an odd rps) must become a
//      whole per-minute rate, not a fractional per-second one k6 rejects
test('fractional arrival rates are expressed per minute', () => {
  const t = base();
  t.flows.jwks.rps = 0.5;
  let o = buildOptions(loadTargets(t), 'load');
  assert.equal(o.scenarios.jwks.rate, 30);
  assert.equal(o.scenarios.jwks.timeUnit, '1m');
  // whole rates keep per-second units
  assert.equal(o.scenarios.auth_login.rate, 2);
  assert.equal(o.scenarios.auth_login.timeUnit, '1s');
  const u = base();
  u.flows.jwks.rps = 1;
  u.scenarios.stress.multiplier = 1.5;
  o = buildOptions(loadTargets(u), 'stress');
  assert.equal(o.scenarios.jwks.rate, 90);
  assert.equal(o.scenarios.jwks.timeUnit, '1m');
  const v = base();
  v.flows.jwks.rps = 0.5;
  o = buildOptions(loadTargets(v), 'spike');
  assert.equal(o.scenarios.jwks.timeUnit, '1m');
  assert.equal(o.scenarios.jwks.startRate, 30);
  for (const st of o.scenarios.jwks.stages) assert.ok(Number.isInteger(st.target) && st.target >= 1);
  for (const sc of Object.values(o.scenarios)) {
    for (const k of ['rate', 'startRate']) if (sc[k] !== undefined) assert.ok(Number.isInteger(sc[k]));
  }
});
