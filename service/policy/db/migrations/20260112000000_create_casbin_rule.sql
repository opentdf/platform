-- +goose Up
-- +goose StatementBegin

-- Create the casbin_rule table for Casbin v2 policy storage
CREATE TABLE IF NOT EXISTS casbin_rule (
    id bigserial PRIMARY KEY,
    ptype varchar(100),
    v0 varchar(100),
    v1 varchar(100),
    v2 varchar(100),
    v3 varchar(100),
    v4 varchar(100),
    v5 varchar(100)
);

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_casbin_rule_ptype ON casbin_rule(ptype);
CREATE INDEX IF NOT EXISTS idx_casbin_rule_v0 ON casbin_rule(v0);
CREATE INDEX IF NOT EXISTS idx_casbin_rule_v1 ON casbin_rule(v1);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_casbin_rule_v1;
DROP INDEX IF EXISTS idx_casbin_rule_v0;
DROP INDEX IF EXISTS idx_casbin_rule_ptype;
DROP TABLE IF EXISTS casbin_rule;

-- +goose StatementEnd
