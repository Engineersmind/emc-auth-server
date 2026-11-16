// perf/seed/teardown.js — issue #218 (FR5)
//
// Deactivates exactly what a seed run created: the application ids, then the
// tenant id, taken from the state file and nowhere else — ownership is by
// construction (the run stamped its own runid into every name), never by
// listing and matching.
//
// Env:
//   PERF_STATE_FILE   required; the seed's state file. Absent, unreadable or
//                     malformed -> exit 1 with ZERO requests sent.
//   PERF_ADMIN_TOKEN  required; an issued admin JWT (15-min life — supply a
//                     fresh one for teardown after a long run).
//
// Outcomes per id: 2xx = deactivated; 404 = reported as "not found" (not
// counted as deleted by us, but not blocking); 401/403 = the admin token was
// rejected or expired — state file KEPT so a retry with a fresh token can
// finish the job; any other failure = exit 1, state kept.
//
// Known limitation: deactivation leaves tenant, app and user rows behind —
// nothing here is hard-deleted.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkTarget, deniedDomains } from '../lib/target-guard.js';

const REFUSED_PATH = fileURLToPath(new URL('../refused-hosts.json', import.meta.url));

export async function main({ env, fetch, fs, log, now }) {
  const fail = (msg) => {
    log(`teardown: ${msg}`);
    return 1;
  };

  const statePath = env.PERF_STATE_FILE;
  if (!statePath) {
    return fail('PERF_STATE_FILE is not set — teardown removes only what a state file records');
  }
  let state;
  try {
    state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch (e) {
    return fail(`state file unreadable or malformed: ${e instanceof Error ? e.message : e}`);
  }
  if (
    !state ||
    typeof state !== 'object' ||
    typeof state.base_origin !== 'string' ||
    !state.tenant ||
    typeof state.tenant.id !== 'string'
  ) {
    return fail('state file malformed: missing base_origin or tenant.id');
  }

  let denied;
  try {
    denied = deniedDomains(JSON.parse(fs.readFileSync(REFUSED_PATH, 'utf8')));
  } catch (e) {
    return fail('cannot read perf/refused-hosts.json — refusing to run without the deny list');
  }
  // The target comes from the state file — the same origin the seed wrote —
  // and is still allowlist-checked: a tampered state file fails closed.
  const guard = checkTarget(state.base_origin, denied);
  if (!guard.ok) {
    return fail(`state target refused (${guard.reason})`);
  }
  const ORIGIN = guard.origin;

  const token = env.PERF_ADMIN_TOKEN;
  if (!token) {
    return fail('PERF_ADMIN_TOKEN is not set — supply a fresh issued admin JWT (15-min life)');
  }

  const del = async (p) => {
    const res = await fetch(ORIGIN + p, {
      method: 'DELETE',
      redirect: 'manual',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status >= 300 && res.status < 400) {
      throw new Error(`unexpected ${res.status} redirect from DELETE ${p}`);
    }
    return res;
  };

  const tid = state.tenant.id;
  const notFound = [];
  const record404 = (what) => notFound.push(what);

  try {
    // Applications first, then the tenant — exactly the ids in the file.
    for (const key of ['web', 'm2m', 'defaults']) {
      const app = state.apps && state.apps[key];
      if (!app || app.id === undefined || app.id === null) continue;
      const res = await del(`/api/v1/tenants/${tid}/applications/${app.id}`);
      if (res.status === 404) {
        record404(`app ${key} (id ${app.id})`);
      } else if (res.status === 401 || res.status === 403) {
        return fail('admin token rejected or expired — supply a fresh PERF_ADMIN_TOKEN; state file kept');
      } else if (!(res.status >= 200 && res.status < 300)) {
        return fail(`deactivate app ${key}: HTTP ${res.status} — state file kept`);
      }
    }

    const res = await del(`/api/v1/tenants/${tid}`);
    if (res.status === 404) {
      record404(`tenant (id ${tid})`);
    } else if (res.status === 401 || res.status === 403) {
      return fail('admin token rejected or expired — supply a fresh PERF_ADMIN_TOKEN; state file kept');
    } else if (!(res.status >= 200 && res.status < 300)) {
      return fail(`deactivate tenant: HTTP ${res.status} — state file kept`);
    }
  } catch (e) {
    return fail(`request failed: ${e instanceof Error ? e.message : e} — state file kept`);
  }

  if (notFound.length > 0) {
    log(`teardown: not found, not counted as deleted: ${notFound.join(', ')}`);
  }
  // Every recorded id answered 2xx or 404 — the file has done its job. The
  // secrets can sit under two names: statePath itself and, when the caller
  // pointed at latest.json, the run file the runid resolves to. Remove both;
  // ENOENT is fine (already gone), anything else leaves credentials behind so
  // it fails loudly.
  const removals = [statePath];
  if (typeof state.runid === 'string' && /^[0-9A-Za-z-]+$/.test(state.runid)) {
    const runPath = path.join(path.dirname(statePath), `${state.runid}.json`);
    if (runPath !== statePath) removals.push(runPath);
  }
  let removalFailed = false;
  for (const p of removals) {
    try {
      fs.unlinkSync(p);
    } catch (e) {
      if (e && e.code === 'ENOENT') continue;
      log(`teardown: deactivated, but removing ${p} failed: ${e instanceof Error ? e.message : e}`);
      removalFailed = true;
    }
  }
  if (removalFailed) return 1;
  // Drop latest.json only when it still points at this run; it may simply not
  // exist, which is not an error.
  try {
    const latestPath = path.join(path.dirname(statePath), 'latest.json');
    const latest = JSON.parse(fs.readFileSync(latestPath, 'utf8'));
    if (latest && latest.runid === state.runid) {
      fs.unlinkSync(latestPath);
    }
  } catch {
    /* no usable latest.json — nothing to clean */
  }
  log('teardown: done — apps and tenant deactivated (deactivation only; rows remain, nothing is hard-deleted)');
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
  }).then((code) => process.exit(code));
}
