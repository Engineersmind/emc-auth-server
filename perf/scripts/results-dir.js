// perf/scripts/results-dir.js — issue #218 (FR6)
//
// Prints the results directory for a run so the Makefile and the workflow can
// mkdir -p it before k6 starts (k6 will not create missing directories):
//
//   RESULTS_DIR=$(GIT_SHA=$(git rev-parse HEAD) node perf/scripts/results-dir.js smoke)
//
// Exits 1 with the validation error when GIT_SHA or the scenario is unusable.

import { resultsDir } from '../lib/results.js';

const scenario = process.argv[2] || 'smoke';
const gitSha = process.env.GIT_SHA || '';

try {
  console.log(resultsDir(new Date(), scenario, gitSha));
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
}
