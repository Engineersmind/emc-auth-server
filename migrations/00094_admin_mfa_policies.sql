-- +goose Up
-- +goose StatementBegin

-- Mandatory multi-factor authentication for administrators.
--
-- Every administrator — tenant owner, co-owner, and platform administrator —
-- must complete a second factor to reach the admin console. There is no
-- "off" switch: an administrator account is the highest-value credential in
-- the system, and NIST SP 800-63B AAL2, the CIS controls and every major
-- identity provider (Okta, Entra, Auth0, GitHub) treat MFA for privileged
-- accounts as a baseline rather than an option.
--
-- The second factor after a password is an authenticator app (TOTP) or an
-- emailed code. A passkey is a SIGN-IN method, not a second factor: with user
-- verification it is already two factors, so a passkey sign-in needs no
-- second step and passkeys are not part of this policy.
--
-- What IS configurable is WHICH factors satisfy the requirement. That is this
-- table: one row per tenant, plus one platform row (tenant_id NULL) that
-- governs platform administrators and every tenant without a row of its own.
-- Resolution is most-specific-wins, matching lockout_policies (00086) and
-- captcha_policies (00090).
--
-- allowed_methods must name at least one method. An empty set would make the
-- requirement impossible to satisfy and lock every administrator out, so the
-- CHECK below refuses it at the storage layer as well as at the API.
CREATE TABLE IF NOT EXISTS admin_mfa_policies (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- NULL is the platform row. Set is a tenant's own policy.
    tenant_id       BIGINT REFERENCES tenants(id) ON DELETE CASCADE,

    -- 'totp'  — authenticator app (RFC 6238), with single-use backup codes.
    -- 'email' — one-time code to the account inbox. In the default so an
    --           administrator always has a fallback, although NIST SP
    --           800-63B §5.1.3.1 does not accept email as an out-of-band
    --           authenticator — a tenant that wants AAL2-strict factors
    --           removes it from its own policy.
    --
    -- Must match auth.DefaultAdminMFAMethods, the fallback when no row can be read.
    allowed_methods TEXT[] NOT NULL DEFAULT '{totp,email}',

    updated_by      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT admin_mfa_policies_methods_nonempty
        CHECK (cardinality(allowed_methods) >= 1),
    CONSTRAINT admin_mfa_policies_methods_valid
        CHECK (allowed_methods <@ ARRAY['totp', 'email']::TEXT[])
);

-- One row per tenant, and exactly one platform row.
CREATE UNIQUE INDEX IF NOT EXISTS admin_mfa_policies_tenant_key
    ON admin_mfa_policies (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS admin_mfa_policies_platform_key
    ON admin_mfa_policies ((tenant_id IS NULL)) WHERE tenant_id IS NULL;

INSERT INTO admin_mfa_policies (tenant_id, allowed_methods)
SELECT NULL, '{totp,email}'
WHERE NOT EXISTS (SELECT 1 FROM admin_mfa_policies WHERE tenant_id IS NULL);

-- The admin console's sign-in is no longer captcha-gated.
--
-- 'session' was the console's own flow (POST /auth/session). Administrators
-- are now protected by mandatory MFA, which is a far stronger control against
-- credential stuffing than a captcha: a correct password alone no longer
-- reaches anything. Lockout and rate limiting still apply. The flow is removed
-- from every stored policy and from the column default so no row keeps naming
-- a flow the gate no longer checks.
UPDATE captcha_policies
SET protected_flows = array_remove(protected_flows, 'session')
WHERE 'session' = ANY (protected_flows);

ALTER TABLE captcha_policies
    ALTER COLUMN protected_flows SET DEFAULT '{login,login_otp,register,forgot_password}';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE captcha_policies
    ALTER COLUMN protected_flows SET DEFAULT '{login,session,login_otp,register,forgot_password}';
DROP TABLE IF EXISTS admin_mfa_policies;
-- +goose StatementEnd
