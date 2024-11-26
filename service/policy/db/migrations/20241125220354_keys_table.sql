-- +goose Up
-- +goose StatementBegin
CREATE TABLE
    IF NOT EXISTS keys (
        id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
        key_access_server_id uuid NOT NULL REFERENCES key_access_servers (id),
        key_id VARCHAR(36) NOT NULL,
        alg VARCHAR(50) NOT NULL,
        public_key TEXT NOT NULL,
        metadata JSONB,
        created_at timestamp,
        updated_at timestamp,
        UNIQUE (key_access_server_id, key_id)
    );

CREATE TABLE
    IF NOT EXISTS attribute_namespace_key_map (
        namespace_id UUID NOT NULL REFERENCES attribute_namespaces (id) ON DELETE CASCADE,
        key_id UUID NOT NULL REFERENCES keys (id) ON DELETE CASCADE,
        PRIMARY KEY (namespace_id, key_id)
    );

CREATE TABLE
    IF NOT EXISTS attribute_definition_key_map (
        attribute_definition_id UUID NOT NULL REFERENCES attribute_definitions (id) ON DELETE CASCADE,
        key_id UUID NOT NULL REFERENCES keys (id) ON DELETE CASCADE,
        PRIMARY KEY (attribute_definition_id, key_id)
    );

CREATE TABLE
    IF NOT EXISTS attribute_value_key_map (
        attribute_value_id UUID NOT NULL REFERENCES attribute_values (id) ON DELETE CASCADE,
        key_id UUID NOT NULL REFERENCES keys (id) ON DELETE CASCADE,
        PRIMARY KEY (attribute_value_id, key_id)
    );

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE keys;

DROP TABLE attribute_namespace_key_map;

DROP TABLE attribute_definition_key_map;

DROP TABLE attribute_value_key_map;

-- +goose StatementEnd