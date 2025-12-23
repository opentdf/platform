-- +goose Up
-- +goose StatementBegin

-- Remove the 'resources' table that was never used in platform 2.0 and should be removed
DROP TABLE IF EXISTS resources;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Recreate the deprecated resources table (SQLite version)
-- INTEGER PRIMARY KEY is SQLite's equivalent of SERIAL
CREATE TABLE IF NOT EXISTS resources
(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    version INTEGER NOT NULL,
    fqn TEXT,
    labels TEXT, -- JSON stored as TEXT
    description TEXT,
    policytype TEXT NOT NULL,
    resource TEXT -- JSON stored as TEXT
);

-- +goose StatementEnd
