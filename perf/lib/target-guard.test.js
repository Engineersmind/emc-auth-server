// perf/lib/target-guard.test.js — issue #218 (FR7)
//
// One test() per URL so every refusal/allowance case is counted and named.
// The denied list comes from the real perf/refused-hosts.json so the data file
// — not a copy embedded here — is what the assertions pin.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkTarget, deniedDomains } from './target-guard.js';

const DENIED = deniedDomains(
  JSON.parse(readFileSync(new URL('../refused-hosts.json', import.meta.url), 'utf8')),
);

const REFUSALS = [
  // why: #218 production domain (F8) must be refused with the explicit reason
  ['https://auth.senie.ai', 'production-domain'],
  // why: #218 scheme case + trailing dot must not launder a production host
  ['HTTPS://AUTH.SENIE.AI./x', 'production-domain'],
  // why: #218 an explicit :443 does not make a production host local
  ['https://auth.senie.ai:443', 'production-domain'],
  // why: #218 sibling production hostname on the same domain
  ['https://emc-auth.senie.ai', 'production-domain'],
  // why: #218 the bare apex is refused as well as subdomains
  ['https://senie.ai', 'production-domain'],
  // why: #218 credentials must never reach the guard's host decision
  ['https://user:pw@auth.senie.ai', 'credentials-in-authority'],
  // why: #218 production domain on http is still production
  ['http://auth.engineersmind.com', 'production-domain'],
  // why: #218 "staging" on a production domain is refused — only real local
  //      targets pass, and staging is wired outside this repo
  ['http://staging.engineersmind.com', 'production-domain'],
  // why: #218 orchestrator-added production domain (F8)
  ['https://pollenx.ai', 'production-domain'],
  // why: #218 subdomain of the orchestrator-added production domain
  ['https://console.pollenx.ai', 'production-domain'],
  // why: #218 a production name under a foreign suffix is still a refused
  //      multi-label DNS name, never an allowed local one
  ['https://auth.senie.ai.example.org', 'dns-name'],
  // why: #218 arbitrary public DNS is refused (allowlist, fail closed)
  ['http://example.com', 'dns-name'],
  // why: #218 host.docker.internal is a multi-label name — refused, not special
  ['http://host.docker.internal:9090', 'dns-name'],
  // why: #218 empty input cannot pass
  ['', 'missing-target'],
  // why: #218 undefined input cannot pass
  [undefined, 'missing-target'],
  // why: #218 leading whitespace must not slip a URL past the parser check
  [' http://localhost', 'invalid-characters'],
  // why: #218 trailing control character must not slip a URL past either
  ['http://localhost\t', 'invalid-characters'],
  // why: #218 non-http(s) schemes are refused even for local hosts
  ['ftp://localhost', 'scheme'],
  // why: #218 host:port without a scheme is refused
  ['localhost:9090', 'scheme'],
  // why: #218 bare scheme with no authority is refused
  ['http://', 'empty-authority'],
  // why: #218 port without a host is refused
  ['http://:9090', 'empty-host'],
  // why: #218 a double trailing dot survives the single-dot strip and is refused
  ['http://localhost..', 'dns-name'],
  // why: #218 port 0 is not a dialable port
  ['http://localhost:0', 'port-range'],
  // why: #218 ports above 65535 are refused
  ['http://localhost:99999', 'port-range'],
  // why: #218 backslash is a parser-disagreement class — refused wholesale
  ['http://localhost\\@auth.senie.ai', 'backslash'],
  // why: #218 %-encoded authority is refused, not decoded
  ['http://localhost%2f@auth.senie.ai', 'authority-encoding'],
  // why: #218 public IPv4 is refused (allowlist, fail closed)
  ['http://3.3.3.3', 'ipv4-range'],
  // why: #218 public IPv4 with a port is still refused
  ['http://52.1.2.3:8080', 'ipv4-range'],
  // why: #218 0.0.0.0 is not a targetable host
  ['http://0.0.0.0', 'ipv4-range'],
  // why: #218 only 127.0.0.1 is loopback — the rest of 127/8 is refused
  ['http://127.0.0.2', 'ipv4-range'],
  // why: #218 cloud metadata link-local is refused
  ['http://169.254.169.254', 'ipv4-range'],
  // why: #218 CGNAT space is refused
  ['http://100.64.0.1', 'ipv4-range'],
  // why: #218 octets above 255 are not a valid IPv4
  ['http://10.0.0.256', 'ipv4-format'],
  // why: #218 leading-zero octets are octal-looking — refused, not decoded
  ['http://010.0.0.1', 'ipv4-format'],
  // why: #218 decimal-packed IPv4 is refused
  ['http://2130706433', 'numeric-host'],
  // why: #218 hex IPv4 is refused
  ['http://0x7f000001', 'numeric-host'],
  // why: #218 only ::1 is allowed; global IPv6 is refused
  ['http://[2600::1]', 'ipv6'],
  // why: #218 ULA IPv6 is refused — no IPv6 LAN is allowlisted beyond ::1
  ['http://[fc00::1]', 'ipv6'],
  // why: #218 IPv4-mapped IPv6 is refused even when the mapped IP is private
  ['http://[::ffff:10.0.0.1]', 'ipv6'],
  // why: #218 Cyrillic lookalike of "localhost" — non-ASCII is refused
  ['http://lоcalhost', 'invalid-characters'],
];

const ALLOWED = [
  // why: #218 the default local compose target must pass
  ['http://localhost:9090', 'localhost', 'http://localhost:9090'],
  // why: #218 host case is normalised, not refused
  ['http://LOCALHOST:9090', 'localhost', 'http://localhost:9090'],
  // why: #218 a single trailing dot is a spelling of the same name
  ['http://localhost.:9090', 'localhost', 'http://localhost:9090'],
  // why: #218 loopback literal is allowed
  ['http://127.0.0.1:9090', '127.0.0.1', 'http://127.0.0.1:9090'],
  // why: #218 ::1 is the one allowed IPv6
  ['http://[::1]:9090', '[::1]', 'http://[::1]:9090'],
  // why: #218 10/8 private LAN is allowed (no port)
  ['http://10.0.0.5', '10.0.0.5', 'http://10.0.0.5'],
  // why: #218 172.16/12 private LAN is allowed
  ['http://172.16.0.1:9090', '172.16.0.1', 'http://172.16.0.1:9090'],
  // why: #218 top of the 172.16/12 range is still inside it
  ['http://172.31.255.255', '172.31.255.255', 'http://172.31.255.255'],
  // why: #218 192.168/16 private LAN is allowed
  ['http://192.168.1.10', '192.168.1.10', 'http://192.168.1.10'],
  // why: #218 a single-label docker service name is allowed
  ['http://emc-auth-server:9090', 'emc-auth-server', 'http://emc-auth-server:9090'],
  // why: #218 path/query/fragment are dropped — callers must use `origin`,
  //      which is rebuilt from the validated authority only
  ['http://localhost:9090/x?y#@auth.senie.ai', 'localhost', 'http://localhost:9090'],
];

for (const [url, reason] of REFUSALS) {
  test(`refuses ${JSON.stringify(url)}`, () => {
    const r = checkTarget(url, DENIED);
    assert.equal(r.ok, false);
    assert.equal(r.reason, reason);
  });
}

for (const [url, host, origin] of ALLOWED) {
  test(`allows ${url}`, () => {
    const r = checkTarget(url, DENIED);
    assert.equal(r.ok, true);
    assert.equal(r.host, host);
    assert.equal(r.origin, origin);
  });
}

// why: #218 a refusal that mentions credentials would leak them into CI logs —
//      the reason names the rule and at most the normalised host, never the raw
//      input (review-proofing A).
test('userinfo refusal text contains neither the id nor the secret', () => {
  const r = checkTarget('https://user:pw@auth.senie.ai', DENIED);
  assert.equal(r.ok, false);
  const text = JSON.stringify(r);
  assert.equal(text.includes('user'), false);
  assert.equal(text.includes('pw'), false);
});

// why: #218 deniedDomains must read the real JSON file shape so the data file
//      — not a hardcoded copy — drives refusals.
test('deniedDomains reads perf/refused-hosts.json', () => {
  assert.deepEqual(DENIED.sort(), ['engineersmind.com', 'pollenx.ai', 'senie.ai']);
});
