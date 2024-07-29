-- +goose Up
-- +goose StatementBegin

DROP TABLE IF EXISTS attribute_value_members;

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

-- +goose StatementEnd