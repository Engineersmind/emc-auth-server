// perf/lib/targets.js — issue #218 (FR2)
//
// Loads and validates perf/targets.json, and turns it into the k6 `options`
// object for one named scenario. Plain ES module — no k6 or node imports — so
// the same file drives the k6 suite, the seed's pool sizing and node:test.
//
// Every flow declares its own thresholds (rps/max_vus, p95, p99, error rate);
// a breached threshold fails the run. Because a threshold on a metric with
// zero samples silently passes in k6, every flow also carries
// http_reqs{flow}:count>=1, a checks{flow} rate floor of 1 - error_rate (a 200
// without the expected body is a failure too), and every arrival-rate scenario carries
// dropped_iterations{scenario}:count==0 — the "VUs/RPS" half of the target.

export const FLOWS = Object.freeze([
  'auth_login',
  'apps_login',
  'apps_register',
  'oauth_client_credentials',
  'oauth_refresh',
  'jwks',
  'apps_me',
]);

export const SCENARIOS = Object.freeze(['smoke', 'load', 'stress', 'soak', 'spike']);

const FLOW_FIELDS = Object.freeze(['rps', 'max_vus', 'p95_ms', 'p99_ms', 'error_rate', 'placeholder']);
const TOP_LEVEL = Object.freeze(['flows', 'scenarios', 'comment']);
const SCENARIO_FIELDS = Object.freeze({
  smoke: Object.freeze(['iterations']),
  load: Object.freeze(['duration']),
  stress: Object.freeze(['duration', 'multiplier']),
  soak: Object.freeze(['duration']),
  spike: Object.freeze(['multiplier', 'stages']),
});
const STAGE_FIELDS = Object.freeze(['duration', 'target']);

const DURATION_RE = /^(\d+(\.\d+)?(ms|s|m|h))+$/;

function fail(msg) {
  throw new Error(`targets: ${msg}`);
}

function isPosNum(v) {
  return typeof v === 'number' && Number.isFinite(v) && v > 0;
}

function isPosInt(v) {
  return Number.isInteger(v) && v > 0;
}

function checkKeys(obj, allowed, where) {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) fail(`${where}: unknown key "${k}"`);
  }
}

function checkDuration(v, where) {
  if (typeof v !== 'string' || !DURATION_RE.test(v)) {
    fail(`${where}: duration must be a k6 duration like "30s", "5m" or "1m30s"`);
  }
}

// loadTargets validates the parsed contents of a targets file and returns it.
// Accepts the object or the raw JSON string. Throws on any violation — a
// malformed file must stop the run before a single request is sent.
export function loadTargets(input) {
  const t = typeof input === 'string' ? JSON.parse(input) : input;
  if (t === null || typeof t !== 'object' || Array.isArray(t)) {
    fail('root must be an object');
  }
  checkKeys(t, TOP_LEVEL, 'root');

  if (t.flows === null || typeof t.flows !== 'object' || Array.isArray(t.flows)) {
    fail('flows must be an object');
  }
  for (const f of FLOWS) {
    const flow = t.flows[f];
    if (flow === undefined) fail(`flows: missing flow "${f}"`);
    if (flow === null || typeof flow !== 'object' || Array.isArray(flow)) {
      fail(`flows.${f}: must be an object`);
    }
    checkKeys(flow, FLOW_FIELDS, `flows.${f}`);
    if (!isPosNum(flow.rps)) fail(`flows.${f}.rps must be a number > 0`);
    if (!isPosInt(flow.max_vus)) fail(`flows.${f}.max_vus must be an integer > 0`);
    if (!isPosNum(flow.p95_ms)) fail(`flows.${f}.p95_ms must be a number > 0`);
    if (!isPosNum(flow.p99_ms) || flow.p99_ms < flow.p95_ms) {
      fail(`flows.${f}.p99_ms must be >= p95_ms`);
    }
    if (typeof flow.error_rate !== 'number' || !(flow.error_rate >= 0 && flow.error_rate <= 1)) {
      fail(`flows.${f}.error_rate must be a number in [0,1]`);
    }
    if (typeof flow.placeholder !== 'boolean') fail(`flows.${f}.placeholder must be a boolean`);
  }
  for (const k of Object.keys(t.flows)) {
    if (!FLOWS.includes(k)) fail(`flows: unknown flow "${k}"`);
  }

  if (t.scenarios === null || typeof t.scenarios !== 'object' || Array.isArray(t.scenarios)) {
    fail('scenarios must be an object');
  }
  for (const s of SCENARIOS) {
    const sc = t.scenarios[s];
    if (sc === undefined) fail(`scenarios: missing scenario "${s}"`);
    if (sc === null || typeof sc !== 'object' || Array.isArray(sc)) {
      fail(`scenarios.${s}: must be an object`);
    }
    checkKeys(sc, SCENARIO_FIELDS[s], `scenarios.${s}`);
    switch (s) {
      case 'smoke':
        if (!isPosInt(sc.iterations)) fail('scenarios.smoke.iterations must be an integer > 0');
        break;
      case 'load':
      case 'soak':
        checkDuration(sc.duration, `scenarios.${s}`);
        break;
      case 'stress':
        checkDuration(sc.duration, 'scenarios.stress');
        if (sc.multiplier !== undefined && !isPosNum(sc.multiplier)) {
          fail('scenarios.stress.multiplier must be a number > 0');
        }
        break;
      case 'spike': {
        if (!isPosNum(sc.multiplier)) fail('scenarios.spike.multiplier must be a number > 0');
        if (!Array.isArray(sc.stages) || sc.stages.length === 0) {
          fail('scenarios.spike.stages must be a non-empty array');
        }
        sc.stages.forEach((st, i) => {
          if (st === null || typeof st !== 'object' || Array.isArray(st)) {
            fail(`scenarios.spike.stages[${i}] must be an object`);
          }
          checkKeys(st, STAGE_FIELDS, `scenarios.spike.stages[${i}]`);
          checkDuration(st.duration, `scenarios.spike.stages[${i}]`);
          if (!isPosNum(st.target)) {
            fail(`scenarios.spike.stages[${i}].target must be a number > 0 (an rps multiplier)`);
          }
        });
        break;
      }
    }
  }
  for (const k of Object.keys(t.scenarios)) {
    if (!SCENARIOS.includes(k)) fail(`scenarios: unknown scenario "${k}"`);
  }

  return t;
}

// Flows whose thresholds are still placeholders — printed as a banner and
// recorded in meta.json so a green placeholder run is never read as an NFR pass.
export function placeholderFlows(targets) {
  return FLOWS.filter((f) => targets.flows[f].placeholder === true);
}

// Peak multiplier the stack will be asked for: the larger of the stress
// multiplier and the highest spike multiplier (scenario-level or any stage).
export function peakFactor(targets) {
  const stress = targets.scenarios.stress.multiplier ?? 2;
  const spike = Math.max(
    targets.scenarios.spike.multiplier,
    ...targets.scenarios.spike.stages.map((s) => s.target),
  );
  return Math.max(stress, spike);
}

// Per-user limiter budgets decide how many seeded accounts each pool needs so
// no single account crosses its per-minute bucket at the peak rate.
//   auth_login: login_account is 10/min per email            -> rps*P*60/10 + 1
//   apps_login: per-user login is overridden to 20/min        -> rps*P*60/20 + 1
//   tokens:     me is overridden to 600/min (sized to 300)    and each token
//               holder pins one user to a VU                  -> VU-based floor
export function poolFloors(targets) {
  const P = peakFactor(targets);
  const f = targets.flows;
  return {
    auth_login: Math.ceil((f.auth_login.rps * P * 60) / 10) + 1,
    apps_login: Math.ceil((f.apps_login.rps * P * 60) / 20) + 1,
    tokens: Math.max(
      Math.ceil(((f.oauth_refresh.max_vus + f.apps_me.max_vus) * P) / 10),
      Math.ceil((f.apps_me.rps * P * 60) / 300),
    ),
  };
}

// App quota sizing from step 4 of the build brief: the perf web app must carry
// the combined app-route rate at peak, the m2m app only client_credentials.
// burst = rpm so a full minute's budget is available at once.
export function appQuotas(targets) {
  const P = peakFactor(targets);
  const f = targets.flows;
  const webRpm = Math.ceil(
    (f.apps_login.rps + f.apps_register.rps + f.apps_me.rps + f.oauth_refresh.rps) * P * 60 * 1.2,
  );
  const m2mRpm = Math.ceil(f.oauth_client_credentials.rps * P * 60 * 1.2);
  return {
    web: { requests_per_minute: webRpm, burst: webRpm },
    m2m: { requests_per_minute: m2mRpm, burst: m2mRpm },
  };
}

// k6's arrival-rate executors take an integer `rate` per `timeUnit`. A whole
// number of requests per second keeps timeUnit '1s'; anything else (rps 0.5, a
// 1.5x stress multiplier on an odd rps) is expressed per minute, rounded to the
// nearest whole request and never below one. k6 spaces arrivals evenly within
// the timeUnit either way.
function perUnit(ratesPerSecond) {
  if (ratesPerSecond.every((r) => Number.isInteger(r))) {
    return { timeUnit: '1s', rates: ratesPerSecond.map((r) => Math.max(1, r)) };
  }
  return { timeUnit: '1m', rates: ratesPerSecond.map((r) => Math.max(1, Math.round(r * 60))) };
}

function allocVUs(rate, p99ms, maxVUs) {
  // Steady-state VUs ~= arrivals/sec * worst expected seconds-per-iteration.
  return Math.min(maxVUs, Math.max(1, Math.ceil((rate * p99ms) / 1000)));
}

function flowThresholds(flow, f) {
  const th = {};
  th[`http_req_duration{flow:${f}}`] = [`p(95)<${flow.p95_ms}`, `p(99)<${flow.p99_ms}`];
  th[`http_req_failed{flow:${f}}`] = [`rate<=${flow.error_rate}`];
  // A zero-sample flow must never read as a pass.
  th[`http_reqs{flow:${f}}`] = ['count>=1'];
  // http_req_failed only sees the status code. A 200 that is not a real
  // success (an OTP challenge with no access_token, a holder that could not
  // log in) fails the flow's check instead, so the same error budget applies
  // to checks. The scenario tag puts every check in that scenario under
  // {flow:<f>}.
  th[`checks{flow:${f}}`] = [`rate>=${Number((1 - flow.error_rate).toFixed(6))}`];
  return th;
}

// buildOptions turns a validated targets object into the k6 `options` value
// for one named scenario. Every flow runs in every scenario under its own
// k6 scenario named after the flow, so the {flow:...} tag selects cleanly.
export function buildOptions(targets, scenario) {
  if (!SCENARIOS.includes(scenario)) {
    fail(`unknown scenario "${scenario}"`);
  }
  const sc = targets.scenarios[scenario];
  const k6scenarios = {};
  const thresholds = {};
  const isArrival = scenario !== 'smoke';

  for (const f of FLOWS) {
    const flow = targets.flows[f];
    const base = { exec: f, tags: { flow: f } };
    if (scenario === 'smoke') {
      k6scenarios[f] = {
        ...base,
        executor: 'per-vu-iterations',
        vus: 1,
        iterations: sc.iterations,
        maxDuration: '10m',
      };
    } else if (scenario === 'spike') {
      const rate = flow.rps;
      const maxVUs = Math.max(1, Math.ceil(flow.max_vus * sc.multiplier));
      const u = perUnit([rate, ...sc.stages.map((s) => rate * s.target)]);
      k6scenarios[f] = {
        ...base,
        executor: 'ramping-arrival-rate',
        startRate: u.rates[0],
        timeUnit: u.timeUnit,
        stages: sc.stages.map((s, i) => ({
          duration: s.duration,
          target: u.rates[i + 1],
        })),
        preAllocatedVUs: allocVUs(rate * sc.multiplier, flow.p99_ms, maxVUs),
        maxVUs,
      };
    } else {
      const mult = scenario === 'stress' ? sc.multiplier ?? 2 : 1;
      const rate = flow.rps * mult;
      const maxVUs = Math.max(1, Math.ceil(flow.max_vus * mult));
      const u = perUnit([rate]);
      k6scenarios[f] = {
        ...base,
        executor: 'constant-arrival-rate',
        rate: u.rates[0],
        timeUnit: u.timeUnit,
        duration: sc.duration,
        preAllocatedVUs: allocVUs(rate, flow.p99_ms, maxVUs),
        maxVUs,
      };
    }
    Object.assign(thresholds, flowThresholds(flow, f));
    if (isArrival) {
      thresholds[`dropped_iterations{scenario:${f}}`] = ['count==0'];
    }
  }

  return {
    scenarios: k6scenarios,
    thresholds,
    // A redirect can only ever pull the run off its allowlisted origin, so a
    // 3xx counts as a failure rather than a silent follow.
    maxRedirects: 0,
    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  };
}
