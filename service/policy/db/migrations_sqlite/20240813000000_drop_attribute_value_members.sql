-- +goose Up
-- +goose StatementBegin

DROP TABLE IF EXISTS attribute_value_members;

-- SQLite: DROP COLUMN requires SQLite 3.35.0+
-- If running older SQLite, this migration will fail and table recreation is needed
ALTER TABLE attribute_values DROP COLUMN members;

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

-- SQLite: UUID[] → TEXT (JSON array)
ALTER TABLE attribute_values ADD COLUMN members TEXT;

-- +goose StatementEnd
