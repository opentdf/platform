-- +goose Up
-- +goose StatementBegin

-- Casbin policy rule table for v2 authorization
-- This table stores authorization policies managed by the Casbin enforcer
CREATE TABLE IF NOT EXISTS casbin_rule
(
    id BIGSERIAL PRIMARY KEY,
    ptype VARCHAR(100),  -- Policy type: 'p' for policy, 'g' for grouping
    v0 VARCHAR(100),     -- Subject (role or user)
    v1 VARCHAR(100),     -- Resource (RPC path)
    v2 VARCHAR(100),     -- Action or dimensions
    v3 VARCHAR(100),     -- Effect (allow/deny)
    v4 VARCHAR(100),     -- Reserved for future use
    v5 VARCHAR(100)      -- Reserved for future use
);

-- Index for efficient policy lookups by type and subject
CREATE INDEX IF NOT EXISTS idx_casbin_rule_ptype_v0 ON casbin_rule(ptype, v0);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_casbin_rule_ptype_v0;
DROP TABLE IF EXISTS casbin_rule;

-- +goose StatementEnd
