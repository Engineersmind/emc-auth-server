-- +goose Up
-- +goose StatementBegin

-- Append-only immutability for audit_logs (compliance: SOC2/ISO27001).
--
-- A BEFORE UPDATE/DELETE trigger rejects every mutation of an audit row unless
-- the session explicitly opts into the maintenance path by setting
-- `emc.audit_maintenance = 'on'`. The application's normal write path only ever
-- INSERTs (via COPY), so it is unaffected and CANNOT alter or delete history —
-- even a compromised app credential or a stray query is blocked at the DB.
--
-- Controlled maintenance (retention purge, GDPR erasure) runs through SECURITY
-- DEFINER functions below that set the flag with SET LOCAL, so the exception is
-- scoped to that one transaction and cannot leak.
CREATE OR REPLACE FUNCTION audit_logs_block_mutations()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_setting('emc.audit_maintenance', true) = 'on' THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;
CREATE TRIGGER audit_logs_immutable
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutations();

-- Retention purge — deletes rows older than `retention_days`. Runs on the
-- maintenance path so the immutability trigger permits the delete. Intended to
-- be called by a scheduled job (pg_cron or the app's retention worker).
-- Returns the number of rows purged.
CREATE OR REPLACE FUNCTION purge_audit_logs(retention_days integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  deleted bigint;
BEGIN
  IF retention_days IS NULL OR retention_days < 1 THEN
    RAISE EXCEPTION 'retention_days must be >= 1';
  END IF;
  SET LOCAL emc.audit_maintenance = 'on';
  WITH gone AS (
    DELETE FROM audit_logs
    WHERE created_at < now() - make_interval(days => retention_days)
    RETURNING 1
  )
  SELECT count(*) INTO deleted FROM gone;
  RETURN deleted;
END;
$$;

-- GDPR erasure — pseudonymizes one user's PII in the audit trail while keeping
-- the (non-PII) security event trail intact. Only the erasable fields are
-- touched; the tamper-evidence hash chain is computed over the non-PII skeleton
-- (see internal/audit), so this does NOT break chain verification.
--
-- user_id is NULLed too: leaving it intact would make an "erased" row instantly
-- re-identifiable via JOIN users ON users.id = audit_logs.user_id. user_id is
-- deliberately excluded from the hash skeleton (chainHash), so nulling it does
-- not break verification.
-- Returns the number of rows pseudonymized.
CREATE OR REPLACE FUNCTION pseudonymize_user_audit(target_user_id bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  affected bigint;
BEGIN
  SET LOCAL emc.audit_maintenance = 'on';
  WITH scrubbed AS (
    UPDATE audit_logs
    SET actor_email = '[erased]',
        ip_address  = NULL,
        user_agent  = '[erased]',
        user_id     = NULL,
        metadata    = jsonb_strip_nulls(
          COALESCE(metadata, '{}'::jsonb)
            - 'response_body' - 'location' - 'stats'
            || '{"_pii_erased": true}'::jsonb
        )
    WHERE user_id = target_user_id
    RETURNING 1
  )
  SELECT count(*) INTO affected FROM scrubbed;
  RETURN affected;
END;
$$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS pseudonymize_user_audit(bigint);
DROP FUNCTION IF EXISTS purge_audit_logs(integer);
DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;
DROP FUNCTION IF EXISTS audit_logs_block_mutations();
-- +goose StatementEnd
