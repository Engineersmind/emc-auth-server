# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x   | ✅ Active support |
| 1.4.x   | ✅ Security patches only |
| < 1.4   | ❌ End of life |

---

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via GitHub's built-in security advisory system:

1. Go to: https://github.com/Engineersmind/emc-auth-server/security/advisories/new
2. Fill in: affected version, description, reproduction steps, and impact assessment
3. You will receive an acknowledgement within **48 hours**
4. We aim to release a patch within **7 days** for critical issues, **14 days** for high severity

If you cannot use GitHub advisories, email the maintainer listed in CODEOWNERS with `[SECURITY]` in the subject line.

---

## Scope

### In Scope
- Authentication bypass (login, token refresh, TOTP)
- Authorization bypass (tenant isolation, permission escalation)
- SQL injection or other injection attacks
- JWT forgery or secret disclosure
- SAML assertion forgery or replay
- API key exposure or brute-force weaknesses
- CORS misconfiguration allowing cross-origin credential theft
- Audit log tampering or bypass
- Information disclosure in error responses

### Out of Scope
- Vulnerabilities requiring physical access to the server
- Denial of service attacks (rate limiting is a known tradeoff, not a bug)
- Issues in dependencies — report those upstream; we will update promptly
- Social engineering or phishing

---

## Security Controls Reference

| Control | Implementation |
|---------|---------------|
| Password hashing | bcrypt cost 12 |
| JWT signing | RS256, per-tenant RSA-2048 key pair, private key AES-256-GCM encrypted at rest, 15-min access TTL. Public keys published at `/tenants/{slug}/.well-known/jwks.json` (ADR-16). |
| Refresh tokens | Atomic rotation, replay returns 401 |
| TOTP secrets | AES-256-GCM encrypted at rest |
| API keys | SHA-256 hash stored, raw shown once |
| SQL queries | pgx v5 positional parameters throughout |
| Rate limiting | 5/min/IP + 10/min/tenant on login |
| Security headers | HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP |
| Audit logging | 21 event types, tenant-scoped + system-wide, fire-and-forget |
| Tenant isolation | All queries scoped to `tenant_id`; cross-tenant requires `tenant:manage` |
| CORS | Per-tenant origin whitelist, Redis-cached |

---

## Disclosure Policy

We follow responsible disclosure. Once a fix is released:
- We will publish a security advisory on GitHub
- The advisory will credit the reporter (unless anonymity is requested)
- We will update this document and the CHANGELOG
