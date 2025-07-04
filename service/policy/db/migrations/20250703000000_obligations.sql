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

CREATE TABLE IF NOT EXISTS obligation_values_standard
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    obligation_definition_id UUID NOT NULL REFERENCES obligation_definitions(id),
    value VARCHAR NOT NULL,
    -- implicit index on unique obligation_definition_id, value
    UNIQUE (obligation_definition_id, value),
    metadata JSONB
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS obligation_definitions;
DROP TABLE IF EXISTS obligation_values_standard;
-- +goose StatementEnd
