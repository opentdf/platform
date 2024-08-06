-- +goose Up
-- +goose StatementBegin

-- Add comments to every column and table

DROP TABLE IF EXISTS resources;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS resources
(
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    namespace VARCHAR NOT NULL,
    version INTEGER NOT NULL,
    fqn VARCHAR,
    labels JSONB,
    description VARCHAR,
    policytype VARCHAR NOT NULL,
    resource JSONB
);

-- +goose StatementEnd