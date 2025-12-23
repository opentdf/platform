-- +goose Up
-- +goose StatementBegin

-- SQLite equivalent of PostgreSQL resources table
-- SERIAL → INTEGER PRIMARY KEY (SQLite auto-increments INTEGER PRIMARY KEY)
-- JSONB → TEXT (JSON stored as text, use json1 extension for queries)
CREATE TABLE IF NOT EXISTS resources
(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    version INTEGER NOT NULL,
    fqn TEXT,
    labels TEXT,
    description TEXT,
    policytype TEXT NOT NULL,
    resource TEXT
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS resources;
-- +goose StatementEnd
