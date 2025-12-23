-- +goose Up
-- +goose StatementBegin

-- SQLite doesn't support adding a column with UNIQUE constraint via ALTER TABLE
-- Use table recreation pattern instead

-- Create new table with the name column (includes UNIQUE constraint)
CREATE TABLE key_access_servers_new (
    id TEXT PRIMARY KEY,
    uri TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    name TEXT UNIQUE
);

-- Copy data from the old table
INSERT INTO key_access_servers_new (id, uri, public_key, metadata, created_at, updated_at)
SELECT id, uri, public_key, metadata, created_at, updated_at
FROM key_access_servers;

-- Drop the old table
DROP TABLE key_access_servers;

-- Rename the new table
ALTER TABLE key_access_servers_new RENAME TO key_access_servers;

-- Recreate the updated_at trigger
CREATE TRIGGER key_access_servers_updated_at
AFTER UPDATE ON key_access_servers
FOR EACH ROW
BEGIN
    UPDATE key_access_servers SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- SQLite: Comments documented here instead of COMMENT ON
-- name: Optional common name of the KAS

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Recreate table without the name column
CREATE TABLE key_access_servers_new (
    id TEXT PRIMARY KEY,
    uri TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Copy data (excluding name)
INSERT INTO key_access_servers_new (id, uri, public_key, metadata, created_at, updated_at)
SELECT id, uri, public_key, metadata, created_at, updated_at
FROM key_access_servers;

-- Drop the old table
DROP TABLE key_access_servers;

-- Rename the new table
ALTER TABLE key_access_servers_new RENAME TO key_access_servers;

-- Recreate the updated_at trigger
CREATE TRIGGER key_access_servers_updated_at
AFTER UPDATE ON key_access_servers
FOR EACH ROW
BEGIN
    UPDATE key_access_servers SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- +goose StatementEnd
