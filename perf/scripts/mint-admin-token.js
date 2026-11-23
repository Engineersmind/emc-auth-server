// perf/scripts/mint-admin-token.js — issue #218
//
// Mints a fresh admin JWT for the seed on a stack where the super-admin is
// subject to the forced administrator MFA policy (the current default). Prints
// ONLY the access token to stdout so it can be captured directly:
//
//   export PERF_ADMIN_TOKEN=$(PERF_ADMIN_PASSWORD="$SEED_ADMIN_PASSWORD" \
//     node perf/scripts/mint-admin-token.js)
//
// Handles all three login outcomes:
//   - plain success          → token printed
//   - requires_otp           → completes the TOTP challenge using a stored or
//     PERF_ADMIN_TOTP_SECRET base32 secret
//   - mfa_enrollment_required→ runs enroll + activate once, then stores the
//     issued secret in perf/.state/admin-totp.json (0600, gitignored) so later
//     mints take the requires_otp path
//
// Env:
//   BASE_URL               default http://localhost:9090 — production refused
//   PERF_ADMIN_EMAIL       default admin@emc.local
//   PERF_ADMIN_PASSWORD    required (use your SEED_ADMIN_PASSWORD locally)
//   PERF_ADMIN_TOTP_SECRET optional base32 secret; overrides the stored one
//   PERF_STATE_DIR         state directory (default perf/.state)
//
// Errors go to stderr; the only stdout line is the token. Nothing logs the
// password or the TOTP secret.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { checkTarget, deniedDomains } from '../lib/target-guard.js';

const REFUSED_PATH = fileURLToPath(new URL('../refused-hosts.json', import.meta.url));
const DEFAULT_STATE_DIR = fileURLToPath(new URL('../.state/', import.meta.url));

const err = (m) => {
  console.error(`mint-admin-token: ${m}`);
  process.exit(1);
};

const denied = deniedDomains(JSON.parse(fs.readFileSync(REFUSED_PATH, 'utf8')));
const guard = checkTarget(process.env.BASE_URL || 'http://localhost:9090', denied);
if (!guard.ok) err(`BASE_URL refused (${guard.reason})`);
const ORIGIN = guard.origin;

const EMAIL = process.env.PERF_ADMIN_EMAIL || 'admin@emc.local';
const PASSWORD = process.env.PERF_ADMIN_PASSWORD;
if (!PASSWORD) err('PERF_ADMIN_PASSWORD is required');

const stateDir = process.env.PERF_STATE_DIR || DEFAULT_STATE_DIR;
const secretPath = path.join(stateDir, 'admin-totp.json');

// ─── TOTP (RFC 6238, SHA-1, 30 s step, 6 digits) ─────────────────────────────

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(s) {
  const clean = s.toUpperCase().replace(/=+$/, '');
  const bits = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) err('TOTP secret is not valid base32');
    for (let b = 4; b >= 0; b--) bits.push((v >> b) & 1);
  }
  const out = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) {
    for (let b = 0; b < 8; b++) out[i] = (out[i] << 1) | bits[i * 8 + b];
  }
  return out;
}

function totp(base32Secret, when = Date.now()) {
  const key = base32Decode(base32Secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(when / 30000)));
  const h = crypto.createHmac('sha1', key).update(counter).digest();
  const off = h[h.length - 1] & 0x0f;
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(code % 1000000).padStart(6, '0');
}

function loadSecret() {
  if (process.env.PERF_ADMIN_TOTP_SECRET) return process.env.PERF_ADMIN_TOTP_SECRET;
  try {
    const j = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
    return j.totp_secret || null;
  } catch {
    return null;
  }
}

function saveSecret(secret) {
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(secretPath, `${JSON.stringify({ email: EMAIL, totp_secret: secret }, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(secretPath, 0o600);
  } catch {
    /* platform without POSIX modes — the gitignored dir is the boundary */
  }
  console.error(`mint-admin-token: TOTP enrolled for ${EMAIL}; secret kept at ${secretPath}`);
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

async function post(p, body) {
  const res = await fetch(ORIGIN + p, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let j = null;
  try {
    j = await res.json();
  } catch {
    /* non-JSON */
  }
  if (res.status >= 300 && res.status < 400) err(`unexpected ${res.status} redirect from ${p}`);
  return { status: res.status, body: j };
}

// ─── Flow ───────────────────────────────────────────────────────────────────

const login = await post('/api/v1/auth/login', { email: EMAIL, password: PASSWORD });
const lb = login.body;
if (!lb) err(`login: HTTP ${login.status}`);
if (lb.mfa_enrollment_required) {
  const enr = await post('/api/v1/auth/login/mfa/enroll', { enrollment_token: lb.enrollment_token });
  if (enr.status !== 200 || !enr.body || !enr.body.otp_uri) err(`mfa enroll: HTTP ${enr.status}`);
  const m = /[?&]secret=([A-Z2-7]+)/i.exec(enr.body.otp_uri);
  if (!m) err('mfa enroll: otp_uri carried no base32 secret');
  const act = await post('/api/v1/auth/login/mfa/activate', {
    enrollment_token: lb.enrollment_token,
    code: totp(m[1]),
  });
  if (act.status !== 200 || !act.body || !act.body.access_token) err(`mfa activate: HTTP ${act.status}`);
  saveSecret(m[1]);
  console.log(act.body.access_token);
} else if (lb.requires_otp) {
  const secret = loadSecret();
  if (!secret) err('login demands OTP but no TOTP secret is known — set PERF_ADMIN_TOTP_SECRET or enroll first');
  const otp = await post('/api/v1/auth/login/otp', { otp_session_token: lb.otp_session_token, code: totp(secret) });
  if (otp.status !== 200 || !otp.body || !otp.body.access_token) err(`login otp: HTTP ${otp.status}`);
  console.log(otp.body.access_token);
} else if (lb.access_token) {
  console.log(lb.access_token);
} else {
  err(`login: unexpected response keys ${JSON.stringify(Object.keys(lb))}`);
}
