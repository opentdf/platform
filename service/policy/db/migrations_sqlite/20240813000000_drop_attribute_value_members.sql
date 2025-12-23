-- +goose Up
-- +goose StatementBegin

-- Drop the attribute_value_members table
-- Note: The PostgreSQL version also drops a 'members' column from attribute_values,
-- but that column was never added in SQLite (PostgreSQL UUID[] arrays don't have
-- a direct SQLite equivalent and were handled differently).
DROP TABLE IF EXISTS attribute_value_members;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS attribute_value_members
(
    id TEXT PRIMARY KEY,
    value_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    member_id TEXT NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    UNIQUE (value_id, member_id)
);

-- +goose StatementEnd
