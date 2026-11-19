// perf/lib/results.js — issue #218 (FR6)
//
// Computes the results directory for one run:
//   docs/perf/<YYYY-MM-DD UTC>/<scenario>-<sha7>-<HHMMSS>Z
//
// Pure function — writes nothing — so node:test can pin the exact path shape.
// gitSha is REQUIRED to be a real lowercase-hex commit SHA (7..40 chars): the
// whole point of the directory name is tying results to the code under test,
// and "unknown" would defeat it (review-proofing A — refuse, don't default).

const SHA_RE = /^[0-9a-f]{7,40}$/;
const SCENARIO_RE = /^[a-z0-9][a-z0-9_-]*$/;

function pad2(n) {
  return String(n).padStart(2, '0');
}

export function resultsDir(now, scenario, gitSha) {
  if (typeof gitSha !== 'string' || !SHA_RE.test(gitSha)) {
    throw new Error('results: GIT_SHA must be a 7-40 char lowercase hex commit sha');
  }
  if (typeof scenario !== 'string' || !SCENARIO_RE.test(scenario)) {
    throw new Error(`results: bad scenario name ${JSON.stringify(scenario)}`);
  }
  const d = now instanceof Date ? now : new Date(now);
  if (Number.isNaN(d.getTime())) {
    throw new Error('results: invalid timestamp');
  }
  const day = `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
  const hms = `${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}`;
  return `docs/perf/${day}/${scenario}-${gitSha.slice(0, 7)}-${hms}Z`;
}
