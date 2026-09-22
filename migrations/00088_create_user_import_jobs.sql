-- +goose Up
-- +goose StatementBegin

-- Durable bulk user import.
--
-- The first async job primitive in this server, and it exists because of one
-- physical fact: a plaintext password must be hashed with Argon2id at m=47104,
-- and the process-wide memoryGuard caps concurrent derivations at NumCPU to
-- keep peak memory predictable. An import that hashes thousands of passwords
-- therefore cannot run inside an HTTP request — it would either time out or
-- saturate the semaphore and queue every concurrent login behind it.
--
-- So the work is written down and drained by a background worker that takes at
-- most a slot or two of that semaphore, leaving the rest for logins. Rows are
-- stored rather than held in memory so the job survives a deploy: a worker that
-- dies at row 3,000 resumes there instead of starting over.

CREATE TABLE user_import_jobs (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- NULL for a tenant-level import. Bound at creation and re-read from this
    -- row by every later stage, so a job id can never become a cross-tenant or
    -- cross-application handle.
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,

    status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),

    -- Amend existing users instead of skipping them. Stored with the job rather
    -- than re-sent, so the setting the operator reviewed in the dry run is the
    -- one the worker applies.
    update_existing BOOLEAN NOT NULL DEFAULT false,

    total_rows     INTEGER NOT NULL DEFAULT 0,
    processed_rows INTEGER NOT NULL DEFAULT 0,
    created_count  INTEGER NOT NULL DEFAULT 0,
    updated_count  INTEGER NOT NULL DEFAULT 0,
    skipped_count  INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,

    -- Who started it. An import creates accounts in bulk; "who ran this, and
    -- when" must be answerable from the job row alone, not only from the audit
    -- trail beside it.
    created_by     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_email    TEXT NOT NULL DEFAULT '',

    -- Set while a worker holds the job. A row whose lease has expired is
    -- reclaimable: the worker that held it died without releasing.
    locked_at      TIMESTAMPTZ,
    locked_by      TEXT,

    error          TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The worker's claim query: oldest pending job, or one whose lease has expired.
CREATE INDEX idx_user_import_jobs_claimable
    ON user_import_jobs (status, created_at)
    WHERE status IN ('pending', 'running');

CREATE INDEX idx_user_import_jobs_tenant
    ON user_import_jobs (tenant_id, created_at DESC);

-- One row per uploaded user.
--
-- The payload is stored rather than the whole document held in memory, which is
-- what makes the job resumable and bounds the worker's footprint regardless of
-- file size.
CREATE TABLE user_import_job_rows (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id      BIGINT NOT NULL REFERENCES user_import_jobs(id) ON DELETE CASCADE,
    -- Position in the uploaded document, zero-based. Reported back one-based so
    -- it matches the line an operator sees in their own file.
    row_index   INTEGER NOT NULL,

    -- The row as uploaded, minus any plaintext password (see below).
    payload     JSONB NOT NULL,

    -- A plaintext password lives here and ONLY here, never in `payload`, so the
    -- two have different lifetimes: this column is overwritten with NULL the
    -- moment the row is processed, while the payload is kept for the report.
    --
    -- Storing a live credential at rest at all is the cost of making the import
    -- durable — the alternative is holding thousands of passwords in worker
    -- memory and losing them on deploy. It is bounded: written once, read once,
    -- and erased on the same transaction that creates the user.
    plaintext_password TEXT,

    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'create', 'update', 'skip', 'reject')),
    reason      TEXT NOT NULL DEFAULT '',
    processed_at TIMESTAMPTZ,

    UNIQUE (job_id, row_index)
);

-- The worker's per-row scan: next unprocessed row of the job it holds.
CREATE INDEX idx_user_import_job_rows_pending
    ON user_import_job_rows (job_id, row_index)
    WHERE status = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_import_job_rows;
DROP TABLE IF EXISTS user_import_jobs;
-- +goose StatementEnd
