-- +goose Up
-- +goose StatementBegin

DROP TABLE IF EXISTS attribute_value_members;

ALTER TABLE attribute_values DROP COLUMN IF EXISTS members;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS attribute_value_members
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value_id UUID NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    member_id UUID NOT NULL REFERENCES attribute_values(id) ON DELETE CASCADE,
    UNIQUE (value_id, member_id)
);

ALTER TABLE attribute_values ADD COLUMN members UUID[];

-- +goose StatementEnd
