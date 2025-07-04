-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS obligation_definitions
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id),
    -- name is a unique identifier for the obligation within the namespace
    name VARCHAR NOT NULL,
    -- implicit index on unique namespace_id, name
    UNIQUE (namespace_id, name),
    metadata JSONB
);

-- CREATE UNIQUE INDEX comp_key ON obligation_definitions (
--     namespace_id,
--     name
-- );

-- obligation_values_standard
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS obligation_definitions;
-- +goose StatementEnd
