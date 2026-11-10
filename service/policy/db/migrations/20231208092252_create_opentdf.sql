-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';

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

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS resources;
-- +goose StatementEnd
