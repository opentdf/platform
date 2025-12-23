-- +goose Up
-- +goose StatementBegin

-- SQLite does not support COMMENT ON statements.
-- This migration is a no-op for SQLite.
-- Comments are documented in the schema creation migrations instead.

-- PostgreSQL version adds comments to tables and columns for documentation.
-- For SQLite, refer to the schema migration files for column documentation.

SELECT 1; -- No-op placeholder

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- No-op: SQLite has no comments to remove

SELECT 1; -- No-op placeholder

-- +goose StatementEnd
