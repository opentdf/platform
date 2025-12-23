-- +goose Up
-- +goose StatementBegin

-- Note: PostgreSQL version creates a function for efficient subject mapping matching
-- with GIN index on JSONB selector_values array.
-- For SQLite:
-- 1. The selector_values column stores JSON array for faster matching
-- 2. Matching is done via json_each() in queries instead of PostgreSQL's && operator
-- 3. A trigger extracts selector values from subject_condition_set.condition

-- Add selector_values column for faster matching
ALTER TABLE subject_condition_set ADD COLUMN selector_values TEXT DEFAULT '[]';

-- Trigger to extract selector values from condition JSON
-- Note: Complex JSONB extraction handled in app layer for initial population
-- Trigger handles updates
CREATE TRIGGER IF NOT EXISTS extract_selector_values_insert
AFTER INSERT ON subject_condition_set
BEGIN
    -- App layer handles extraction - this trigger placeholder for future enhancement
    UPDATE subject_condition_set SET selector_values = '[]' WHERE id = NEW.id AND selector_values IS NULL;
END;

CREATE TRIGGER IF NOT EXISTS extract_selector_values_update
AFTER UPDATE OF condition ON subject_condition_set
BEGIN
    -- App layer handles re-extraction when condition changes
    UPDATE subject_condition_set SET selector_values = '[]' WHERE id = NEW.id AND selector_values IS NULL;
END;

-- Note: The actual selector value extraction is performed by the PolicyDBClient
-- when creating or updating subject_condition_sets, as SQLite lacks the complex
-- JSONB functions needed for nested JSON array element extraction.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS extract_selector_values_update;
DROP TRIGGER IF EXISTS extract_selector_values_insert;

-- Recreate table without selector_values column (SQLite limitation)
CREATE TABLE IF NOT EXISTS subject_condition_set_new (
    id TEXT PRIMARY KEY,
    condition TEXT,
    metadata TEXT,
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO subject_condition_set_new (id, condition, metadata, created_at, updated_at)
SELECT id, condition, metadata, created_at, updated_at FROM subject_condition_set;

DROP TABLE subject_condition_set;
ALTER TABLE subject_condition_set_new RENAME TO subject_condition_set;

-- +goose StatementEnd
