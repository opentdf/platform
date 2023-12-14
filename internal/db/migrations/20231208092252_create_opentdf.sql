-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

CREATE SCHEMA IF NOT EXISTS opentdf;

CREATE TABLE IF NOT EXISTS opentdf.resources
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

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
