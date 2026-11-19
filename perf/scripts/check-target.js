// perf/scripts/check-target.js — issue #218 (FR7)
//
// CLI wrapper over perf/lib/target-guard.js, used by the GitHub Actions smoke
// workflow and by humans before pointing the suite anywhere:
//
//   node perf/scripts/check-target.js <url>
//
// Prints "OK <host>" and exits 0 on an allowed target; prints "REFUSED
// <reason> [<host>]" and exits 1 otherwise — including a missing argument. The
// refusal reason never echoes the raw URL (it may carry credentials).

import { readFileSync } from 'node:fs';
import { checkTarget, deniedDomains } from '../lib/target-guard.js';

function loadDenied() {
  try {
    const parsed = JSON.parse(
      readFileSync(new URL('../refused-hosts.json', import.meta.url), 'utf8'),
    );
    return deniedDomains(parsed);
  } catch {
    return null;
  }
}

const denied = loadDenied();
if (denied === null) {
  console.error('REFUSED denied-list-unreadable');
  process.exit(1);
}

const raw = process.argv[2];
if (raw === undefined) {
  console.error('REFUSED missing-target');
  process.exit(1);
}

const r = checkTarget(raw, denied);
if (!r.ok) {
  console.error(`REFUSED ${r.reason}${r.host !== undefined ? ` ${r.host}` : ''}`);
  process.exit(1);
}
console.log(`OK ${r.host}`);
