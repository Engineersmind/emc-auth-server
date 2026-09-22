-- +goose Up
-- +goose StatementBegin

-- Per-row attempt tracking for bulk user imports.
--
-- An infrastructure failure on a row is not a verdict: the row stays pending
-- and is retried, which is what stops one connection blip from writing off
-- every remaining row of a 10,000-row file. But "retry forever" is the other
-- failure mode — a row that fails the same way on every attempt (a column the
-- database will never accept, an application row deleted mid-import) leaves the
-- job in `running` indefinitely, reclaimed every lease TTL, with nothing in the
-- progress response telling an operator the difference between slow and stuck.
--
-- So an attempt is counted, and past a bound the row is given a terminal
-- verdict and the job carries on. Retrying a transient failure is still free;
-- only the reproducible one is eventually written off, and it is written off
-- visibly rather than silently.
ALTER TABLE user_import_job_rows
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
    -- The last infrastructure failure seen on this row. Kept separately from
    -- `reason`, which is the operator-facing verdict: this one is diagnostic
    -- and is only ever read by an administrator looking at a stuck job.
    ADD COLUMN last_error TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE user_import_job_rows
    DROP COLUMN IF EXISTS attempts,
    DROP COLUMN IF EXISTS last_error;
-- +goose StatementEnd
