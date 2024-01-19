-- +goose Up
-- +goose StatementBegin
CREATE SCHEMA IF NOT EXISTS opentdf;

CREATE TYPE attribute_definition_rule AS ENUM ('UNSPECIFIED', 'ALL_OF', 'ANY_OF', 'HIERARCHY');
CREATE TYPE subject_mappings_operator AS ENUM ('UNSPECIFIED', 'IN', 'NOT_IN');

CREATE TABLE IF NOT EXISTS opentdf.namespaces
(
    id UUID PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS opentdf.attribute_definitions
(
    id UUID PRIMARY KEY,
    namespace_id UUID NOT NULL REFERENCES opentdf.namespaces(id),
    name VARCHAR NOT NULL,
    rule attribute_definition_rule NOT NULL,
    metadata JSONB,
    UNIQUE (namespace_id, name)
);

CREATE TABLE IF NOT EXISTS opentdf.attribute_values
(
    id UUID PRIMARY KEY,
    attribute_definition_id UUID NOT NULL REFERENCES opentdf.attribute_definitions(id),
    value VARCHAR NOT NULL,
    members UUID[] NOT NULL,
    metadata JSONB,
    UNIQUE (attribute_definition_id, value)
);

CREATE TABLE IF NOT EXISTS opentdf.key_access_servers
(
    id UUID PRIMARY KEY,
    key_access_server VARCHAR NOT NULL UNIQUE,
    public_key VARCHAR NOT NULL,
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS opentdf.attribute_definition_key_access_grants
(
    attribute_definition_id UUID NOT NULL REFERENCES opentdf.attribute_definitions(id),
    key_access_server_id UUID NOT NULL REFERENCES opentdf.key_access_servers(id),
    PRIMARY KEY (attribute_definition_id, key_access_server_id)
);

CREATE TABLE IF NOT EXISTS opentdf.attribute_value_key_access_grants
(
    attribute_value_id UUID NOT NULL REFERENCES opentdf.attribute_values(id),
    key_access_server_id UUID NOT NULL REFERENCES opentdf.key_access_servers(id),
    PRIMARY KEY (attribute_value_id, key_access_server_id)
);

CREATE TABLE IF NOT EXISTS opentdf.resource_mappings
(
    id UUID PRIMARY KEY,
    attribute_value_id UUID NOT NULL REFERENCES opentdf.attribute_values(id),
    name VARCHAR NOT NULL,
    terms VARCHAR[],
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS opentdf.subject_mappings
(
    id UUID PRIMARY KEY,
    attribute_value_id UUID NOT NULL REFERENCES opentdf.attribute_values(id),
    operator subject_mappings_operator NOT NULL,
    subject_attribute VARCHAR NOT NULL,
    subject_attribute_values VARCHAR[],
    metadata JSONB
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS opentdf.key_access_servers;
DROP TABLE IF EXISTS opentdf.subject_mappings;
DROP TABLE IF EXISTS opentdf.resource_mappings;
DROP TABLE IF EXISTS opentdf.attribute_value_key_access_grants;
DROP TABLE IF EXISTS opentdf.attribute_definition_key_access_grants;
DROP TABLE IF EXISTS opentdf.attribute_values;
DROP TABLE IF EXISTS opentdf.attribute_definitions;
DROP TABLE IF EXISTS opentdf.namespaces;

DELETE TYPE attribute_definition_rule;
DELETE TYPE subject_mappings_operator;
-- +goose StatementEnd