-- +goose Up
-- +goose StatementBegin

-- Add active column to track soft-delete state
-- SQLite doesn't support ADD COLUMN IF NOT EXISTS, but we can use a workaround
-- SQLite uses INTEGER for boolean (0 = false, 1 = true)

ALTER TABLE attribute_namespaces ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE attribute_definitions ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE attribute_values ADD COLUMN active INTEGER NOT NULL DEFAULT 1;

-- Note: The PostgreSQL version uses a complex PL/pgSQL trigger for cascade deactivation.
-- In SQLite, we implement cascade deactivation in the application layer (PolicyDBClient)
-- because SQLite triggers cannot use dynamic SQL like PostgreSQL's EXECUTE format().
--
-- The following simple triggers could be added if needed for basic cascade:
-- However, per the implementation plan, we defer this to application-layer emulation.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- If rolling back, delete deactivated records first
DELETE FROM attribute_values WHERE active = 0;
DELETE FROM attribute_definitions WHERE active = 0;
DELETE FROM attribute_namespaces WHERE active = 0;

-- SQLite requires recreating tables to drop columns (pre-3.35.0)
-- For SQLite 3.35.0+, ALTER TABLE DROP COLUMN is supported
-- We'll use the modern syntax assuming SQLite 3.35.0+

ALTER TABLE attribute_namespaces DROP COLUMN active;
ALTER TABLE attribute_definitions DROP COLUMN active;
ALTER TABLE attribute_values DROP COLUMN active;

-- +goose StatementEnd
