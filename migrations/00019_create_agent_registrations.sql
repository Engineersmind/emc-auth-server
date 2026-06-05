-- +goose Up
-- +goose StatementBegin
CREATE TABLE agent_registrations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    agent_type  TEXT        NOT NULL CHECK (agent_type IN ('llm', 'tool', 'orchestrator', 'service')),
    capabilities TEXT[]     NOT NULL DEFAULT '{}',
    key_hash    TEXT        NOT NULL UNIQUE,
    key_prefix  TEXT        NOT NULL,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_agent_registrations_tenant_id ON agent_registrations (tenant_id);
CREATE INDEX idx_agent_registrations_key_hash  ON agent_registrations (key_hash);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS agent_registrations;
-- +goose StatementEnd
