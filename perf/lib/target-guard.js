// perf/lib/target-guard.js — issue #218 (FR7)
//
// Decides whether a base URL is an acceptable perf-test target. The policy is
// an ALLOWLIST, fail closed: localhost, loopback, private-LAN IPv4, ::1 and
// single-label docker service names are in; every public or ambiguous form is
// out. Known production domains are refused FIRST so their denial carries the
// explicit reason "production-domain".
//
// This module is deliberately free of k6 and node imports so the same file is
// loadable by k6 (perf/k6/main.js), by the seed/teardown scripts and by
// node:test. Callers load the denied-domain list themselves (k6 uses open(),
// node uses fs) and pass it in — see deniedDomains().
//
// The URL is parsed by hand because there is no WHATWG URL global inside k6,
// and because Node's fetch and Go's net/url disagree on exactly the inputs we
// refuse (whitespace, backslashes, %-encoded authority, non-ASCII, userinfo,
// unbracketed IPv6, decimal/octal/hex IPv4). Rather than guess which parser a
// middlebox used, we refuse the whole class.
//
// contract: checkTarget(raw, deniedHosts) ->
//   { ok: true, origin, host } | { ok: false, reason, host? }
//
// `origin` is rebuilt as scheme://host[:port] from the VALIDATED parts. Any
// path, query or fragment in `raw` is dropped — callers must build every
// request URL from `origin`, never from `raw`. `reason` names the rule that
// fired and `host` (when present) is the normalised host — never the raw
// input, never userinfo, never query.

const SCHEMES = new Set(['http', 'https']);

// Single-label docker-compose service names, e.g. "emc-auth-server".
const DOCKER_NAME = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

// Pulls the domain strings out of the parsed perf/refused-hosts.json shape
// ({ denied: [{ domain, comment }] }) and accepts plain string arrays too, so
// every caller can pass one JSON file.
export function deniedDomains(parsed) {
  if (Array.isArray(parsed)) {
    return parsed.map((d) => entryDomain(d)).filter(Boolean);
  }
  if (parsed && Array.isArray(parsed.denied)) {
    return parsed.denied.map((d) => entryDomain(d)).filter(Boolean);
  }
  return [];
}

function entryDomain(d) {
  if (typeof d === 'string') return d.toLowerCase();
  if (d && typeof d.domain === 'string') return d.domain.toLowerCase();
  return '';
}

function refuse(reason, host) {
  const out = { ok: false, reason };
  if (host !== undefined) out.host = host;
  return out;
}

export function checkTarget(raw, deniedHosts = []) {
  if (typeof raw !== 'string' || raw.length === 0) {
    return refuse('missing-target');
  }

  // Printable ASCII only. One test refuses every whitespace and control
  // character (leading/trailing spaces, tabs, CR/LF) AND every non-ASCII byte
  // (punycode escapes, Cyrillic lookalikes like "lоcalhost"). The parsers
  // disagree on all of these, so the whole class is refused.
  if (/[^\x21-\x7E]/.test(raw)) {
    return refuse('invalid-characters');
  }
  // Backslash is a path separator to some parsers and data to others — a
  // "http://good\evil" ambiguity we refuse outright.
  if (raw.includes('\\')) {
    return refuse('backslash');
  }

  const schemeEnd = raw.indexOf('://');
  if (schemeEnd <= 0 || !/^[a-zA-Z][a-zA-Z0-9+.-]*$/.test(raw.slice(0, schemeEnd))) {
    return refuse('scheme');
  }
  const scheme = raw.slice(0, schemeEnd).toLowerCase();
  if (!SCHEMES.has(scheme)) {
    return refuse('scheme');
  }

  const rest = raw.slice(schemeEnd + 3);
  const authority = rest.split(/[/?#]/)[0];
  if (authority.length === 0) {
    return refuse('empty-authority');
  }
  // %-encoding inside the authority is how "localhost%2f@evil" disagreements
  // start; refuse rather than decode.
  if (authority.includes('%')) {
    return refuse('authority-encoding');
  }
  // userinfo. The reason deliberately names the rule, never the value — the
  // authority may carry credentials that must not be echoed back.
  if (authority.includes('@')) {
    return refuse('credentials-in-authority');
  }

  // Split host / port. Brackets are the only legal IPv6 form.
  let host;
  let port = null;
  let bracketed = false;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) {
      return refuse('ipv6-brackets');
    }
    bracketed = true;
    host = authority.slice(1, close);
    const tail = authority.slice(close + 1);
    if (tail.length > 0) {
      if (!tail.startsWith(':')) {
        return refuse('port');
      }
      port = tail.slice(1);
    }
  } else {
    const firstColon = authority.indexOf(':');
    if (firstColon < 0) {
      host = authority;
    } else if (authority.indexOf(':', firstColon + 1) >= 0) {
      // More than one ':' without brackets can only be an unbracketed IPv6.
      return refuse('ipv6-unbracketed');
    } else {
      host = authority.slice(0, firstColon);
      port = authority.slice(firstColon + 1);
    }
  }

  if (port !== null) {
    if (!/^[0-9]{1,5}$/.test(port)) {
      return refuse('port');
    }
    const p = parseInt(port, 10);
    if (p < 1 || p > 65535) {
      return refuse('port-range');
    }
  }

  let hostNorm = host.toLowerCase();
  if (!bracketed) {
    // Strip at most ONE trailing dot ("localhost." is a spelling of
    // "localhost"); a second one leaves the name unrecognised and refused.
    if (hostNorm.endsWith('.')) {
      hostNorm = hostNorm.slice(0, -1);
    }
  }
  if (hostNorm.length === 0) {
    return refuse('empty-host');
  }

  // Deny list FIRST: a production domain is refused with the explicit reason
  // 'production-domain' before the allowlist logic can mislabel it.
  for (const d of deniedHosts) {
    if (d && (hostNorm === d || hostNorm.endsWith('.' + d))) {
      return refuse('production-domain', hostNorm);
    }
  }

  if (bracketed) {
    if (hostNorm === '::1') {
      return allow(scheme, '[::1]', port);
    }
    return refuse('ipv6', hostNorm);
  }

  if (hostNorm === 'localhost') {
    return allow(scheme, hostNorm, port);
  }
  if (hostNorm === '127.0.0.1') {
    return allow(scheme, hostNorm, port);
  }

  // Numeric-dotted hosts must be a STRICT dotted quad: four decimal octets,
  // 0-255, no leading zeros. 10/8, 172.16/12 and 192.168/16 are in; every
  // other range — public, 0.0.0.0, the rest of 127/8, link-local metadata
  // 169.254/16, CGNAT 100.64/10 — is refused.
  if (/^[0-9]+(\.[0-9]+)+$/.test(hostNorm)) {
    const parts = hostNorm.split('.');
    let strict = parts.length === 4;
    const octets = [];
    if (strict) {
      for (const p of parts) {
        if (!/^[0-9]{1,3}$/.test(p) || (p.length > 1 && p.startsWith('0'))) {
          strict = false;
          break;
        }
        octets.push(parseInt(p, 10));
      }
    }
    if (!strict || octets.some((o) => o > 255)) {
      return refuse('ipv4-format', hostNorm);
    }
    const [a, b] = octets;
    const priv =
      a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
    if (!priv) {
      return refuse('ipv4-range', hostNorm);
    }
    return allow(scheme, hostNorm, port);
  }

  // Alternate IPv4 spellings that parsers variously collapse: bare decimal
  // (2130706433), hex (0x7f000001), octal — all refused.
  if (/^[0-9]+$/.test(hostNorm) || /^0x[0-9a-f]+$/i.test(hostNorm) || /^0[0-9]+$/.test(hostNorm)) {
    return refuse('numeric-host', hostNorm);
  }

  // A single-label docker service name is allowed; any multi-label DNS name
  // (host.docker.internal included) is refused — an allowlisted name list
  // would be the only safe extension, and we don't keep one.
  if (DOCKER_NAME.test(hostNorm)) {
    return allow(scheme, hostNorm, port);
  }

  return refuse('dns-name', hostNorm);
}

function allow(scheme, hostNorm, port) {
  return {
    ok: true,
    host: hostNorm,
    origin: `${scheme}://${hostNorm}${port !== null ? ':' + port : ''}`,
  };
}
