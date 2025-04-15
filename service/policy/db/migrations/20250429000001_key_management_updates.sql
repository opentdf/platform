-- +goose Up
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trigger_update_was_mapped_namespace ON attribute_namespace_public_key_map;

DROP TRIGGER IF EXISTS trigger_update_was_mapped_definition ON attribute_definition_public_key_map;

DROP TRIGGER IF EXISTS trigger_update_was_mapped_value ON attribute_value_key_map;

DROP TRIGGER IF EXISTS maintain_active_key ON public_keys;

DROP FUNCTION IF EXISTS update_active_key;

DROP VIEW IF EXISTS active_value_public_keys_view;

DROP VIEW IF EXISTS active_definition_public_keys_view;

DROP VIEW IF EXISTS active_namespace_public_keys_view;

DROP TABLE IF EXISTS attribute_namespace_public_key_map;

DROP TABLE IF EXISTS attribute_definition_public_key_map;

DROP TABLE IF EXISTS attribute_value_public_key_map;

DROP TABLE IF EXISTS public_keys;

DROP FUNCTION IF EXISTS update_was_mapped;

ALTER TABLE key_access_servers
ADD COLUMN IF NOT EXISTS source_type VARCHAR;

CREATE TABLE IF NOT EXISTS
    provider_config (
        id UUID DEFAULT gen_random_uuid () CONSTRAINT provider_config_pkey PRIMARY KEY,
        provider_name VARCHAR(255) NOT NULL,
        config JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        metadata JSONB
    );

COMMENT ON TABLE provider_config IS 'Table to store key provider configurations';

COMMENT ON COLUMN provider_config.id IS 'Unique identifier for the provider configuration';

COMMENT ON COLUMN provider_config.provider_name IS 'Name of the key provider';

COMMENT ON COLUMN provider_config.config IS 'Configuration details for the key provider';

COMMENT ON COLUMN provider_config.created_at IS 'Timestamp when the provider configuration was created';

COMMENT ON COLUMN provider_config.updated_at IS 'Timestamp when the provider configuration was last updated';

COMMENT ON COLUMN provider_config.metadata IS 'Additional metadata for the provider configuration';

CREATE TABLE IF NOT EXISTS
    asym_key (
        id UUID DEFAULT gen_random_uuid () CONSTRAINT asym_key_pkey PRIMARY KEY,
        key_id VARCHAR(36) NOT NULL UNIQUE,
        key_algorithm INT NOT NULL,
        key_status INT NOT NULL,
        key_mode INT NOT NULL,
        public_key_ctx JSONB,
        private_key_ctx JSONB,
        expiration TIMESTAMP,
        provider_config_id UUID CONSTRAINT asym_key_provider_config_fk REFERENCES provider_config (id),
        metadata JSONB,
        created_at TIMESTAMP,
        updated_at TIMESTAMP
    );

COMMENT ON TABLE asym_key IS 'Table to store asymmetric keys';

COMMENT ON COLUMN asym_key.id IS 'Unique identifier for the key';

COMMENT ON COLUMN asym_key.key_status IS 'Indicates the status of the key Active, Inactive, Compromised, or Expired';

COMMENT ON COLUMN asym_key.key_mode IS 'Indicates whether the key is stored LOCAL or REMOTE';

COMMENT ON COLUMN asym_key.key_id IS 'Unique identifier for the key';

COMMENT ON COLUMN asym_key.key_algorithm IS 'Algorithm used to generate the key';

COMMENT ON COLUMN asym_key.public_key_ctx IS 'Public Key Context is a json defined structure of the public key';

COMMENT ON COLUMN asym_key.private_key_ctx IS 'Private Key Context is a json defined structure of the private key. Could include information like PEM encoded key, or external key id information';

COMMENT ON COLUMN asym_key.provider_config_id IS 'Reference the provider configuration for this key';

COMMENT ON COLUMN asym_key.metadata IS 'Additional metadata for the key';

COMMENT ON COLUMN asym_key.created_at IS 'Timestamp when the key was created';

COMMENT ON COLUMN asym_key.updated_at IS 'Timestamp when the key was last updated';

CREATE TABLE IF NOT EXISTS
    sym_key (
        id UUID DEFAULT gen_random_uuid () CONSTRAINT sym_key_pkey PRIMARY KEY,
        key_id VARCHAR(36) NOT NULL UNIQUE,
        key_status INT NOT NULL,
        key_mode INT NOT NULL,
        key_value bytea,
        provider_config_id UUID CONSTRAINT sym_key_provider_config_fk REFERENCES provider_config (id),
        created_at TIMESTAMP,
        updated_at TIMESTAMP,
        metadata JSONB
    );

COMMENT ON TABLE sym_key IS 'Table to store symmetric keys';

COMMENT ON COLUMN sym_key.id IS 'Unique identifier for the key';

COMMENT ON COLUMN sym_key.key_id IS 'Unique identifier for the key';

COMMENT ON COLUMN sym_key.key_status IS 'Indicates the status of the key Active, Inactive, Compromised, or Expired';

COMMENT ON COLUMN sym_key.key_mode IS 'Indicates whether the key is stored LOCAL or REMOTE';

COMMENT ON COLUMN sym_key.key_value IS 'Key value in binary format';

COMMENT ON COLUMN sym_key.provider_config_id IS 'Reference the provider configuration for this key';

COMMENT ON COLUMN sym_key.created_at IS 'Timestamp when the key was created';

COMMENT ON COLUMN sym_key.updated_at IS 'Timestamp when the key was last updated';

COMMENT ON COLUMN sym_key.metadata IS 'Additional metadata for the key';

CREATE TABLE IF NOT EXISTS
    key_access_server_keys (
        id UUID DEFAULT gen_random_uuid () CONSTRAINT key_access_server_keys_pkey PRIMARY KEY,
        key_access_server_id UUID NOT NULL CONSTRAINT key_access_server_fk REFERENCES key_access_servers (id) ON DELETE CASCADE,
        UNIQUE (key_access_server_id, key_id) -- Prevents duplicate public keys for the same KAS by key_id and alg
    ) INHERITS (asym_key);

CREATE TABLE IF NOT EXISTS
    attribute_namespace_public_key_map (
        namespace_id UUID NOT NULL CONSTRAINT namespace_fk REFERENCES attribute_namespaces (id) ON DELETE CASCADE,
        key_access_server_key_id UUID NOT NULL CONSTRAINT key_access_server_keys_fk REFERENCES key_access_server_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (namespace_id, key_access_server_key_id)
    );

COMMENT ON TABLE attribute_namespace_public_key_map IS 'Table to map public keys to attribute namespaces';

COMMENT ON COLUMN attribute_namespace_public_key_map.namespace_id IS 'Foreign key to the attribute namespace';

COMMENT ON COLUMN attribute_namespace_public_key_map.key_access_server_key_id IS 'Foreign key to the key access server public key for wrapping symmetric keys';

CREATE TABLE IF NOT EXISTS
    attribute_definition_public_key_map (
        definition_id UUID NOT NULL CONSTRAINT definition_fk REFERENCES attribute_definitions (id) ON DELETE CASCADE,
        key_access_server_key_id UUID NOT NULL CONSTRAINT key_access_server_keys_fk REFERENCES key_access_server_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (definition_id, key_access_server_key_id)
    );

COMMENT ON TABLE attribute_definition_public_key_map IS 'Table to map public keys to attribute definitions';

COMMENT ON COLUMN attribute_definition_public_key_map.definition_id IS 'Foreign key to the attribute definition';

COMMENT ON COLUMN attribute_definition_public_key_map.key_access_server_key_id IS 'Foreign key to the key access server public key for wrapping symmetric keys';

CREATE TABLE IF NOT EXISTS
    attribute_value_public_key_map (
        value_id UUID NOT NULL CONSTRAINT value_fk REFERENCES attribute_values (id) ON DELETE CASCADE,
        key_access_server_key_id UUID NOT NULL CONSTRAINT key_access_server_keys_fk REFERENCES key_access_server_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (value_id, key_access_server_key_id)
    );

COMMENT ON TABLE attribute_value_public_key_map IS 'Table to map public keys to attribute values';

COMMENT ON COLUMN attribute_value_public_key_map.value_id IS 'Foreign key to the attribute value';

COMMENT ON COLUMN attribute_value_public_key_map.key_access_server_key_id IS 'Foreign key to the key access server public key for wrapping symmetric keys';

CREATE VIEW
    active_namespace_public_keys_view AS
SELECT
    km.namespace_id,
    JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id',
            ky.id,
            'key_status',
            ky.key_status,
            'public_key',
            JSON_BUILD_OBJECT(
                'key_algorithm',
                ky.key_algorithm,
                'key_id',
                ky.key_id,
                'public_key_ctx',
                ky.public_key_ctx
            ),
            'kas',
            JSONB_BUILD_OBJECT('id', kas.id, 'uri', kas.uri, 'name', kas.name)
        )
    ) AS keys
FROM
    key_access_server_keys AS ky
    INNER JOIN attribute_namespace_public_key_map AS km ON ky.id = km.key_access_server_key_id
    LEFT JOIN key_access_servers AS kas ON ky.key_access_server_id = kas.id
WHERE
    ky.key_status = 1
GROUP BY
    km.namespace_id;

COMMENT ON VIEW active_namespace_public_keys_view IS 'View to retrieve active public keys mapped to attribute namespaces';

CREATE VIEW
    active_definition_public_keys_view AS
SELECT
    km.definition_id,
    JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id',
            ky.id,
            'key_status',
            ky.key_status,
            'public_key',
            JSON_BUILD_OBJECT(
                'key_algorithm',
                ky.key_algorithm,
                'key_id',
                ky.key_id,
                'public_key_ctx',
                ky.public_key_ctx
            ),
            'kas',
            JSONB_BUILD_OBJECT('id', kas.id, 'uri', kas.uri, 'name', kas.name)
        )
    ) AS keys
FROM
    key_access_server_keys AS ky
    INNER JOIN attribute_definition_public_key_map AS km ON ky.id = km.key_access_server_key_id
    LEFT JOIN key_access_servers AS kas ON ky.key_access_server_id = kas.id
WHERE
    ky.key_status = 1
GROUP BY
    km.definition_id;

COMMENT ON VIEW active_definition_public_keys_view IS 'View to retrieve active public keys mapped to attribute definitions';

CREATE VIEW
    active_value_public_keys_view AS
SELECT
    km.value_id,
    JSONB_AGG(
        DISTINCT JSONB_BUILD_OBJECT(
            'id',
            ky.id,
            'key_status',
            ky.key_status,
            'public_key',
            JSON_BUILD_OBJECT(
                'key_algorithm',
                ky.key_algorithm,
                'key_id',
                ky.key_id,
                'public_key_ctx',
                ky.public_key_ctx
            ),
            'kas',
            JSONB_BUILD_OBJECT('id', kas.id, 'uri', kas.uri, 'name', kas.name)
        )
    ) AS keys
FROM
    key_access_server_keys AS ky
    INNER JOIN attribute_value_public_key_map AS km ON ky.id = km.key_access_server_key_id
    LEFT JOIN key_access_servers AS kas ON ky.key_access_server_id = kas.id
WHERE
    ky.key_status = 1
GROUP BY
    km.value_id;

COMMENT ON VIEW active_value_public_keys_view IS 'View to retrieve active public keys mapped to attribute values';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP VIEW IF EXISTS active_value_public_keys_view;

DROP VIEW IF EXISTS active_definition_public_keys_view;

DROP VIEW IF EXISTS active_namespace_public_keys_view;

DROP TABLE IF EXISTS attribute_value_public_key_map;

DROP TABLE IF EXISTS attribute_definition_public_key_map;

DROP TABLE IF EXISTS attribute_namespace_public_key_map;

DROP TABLE IF EXISTS key_access_server_keys;

DROP TABLE IF EXISTS sym_key;

DROP TABLE IF EXISTS asym_key;

DROP TABLE IF EXISTS provider_config;

ALTER TABLE key_access_servers
DROP COLUMN IF EXISTS source_type;

-- +goose StatementEnd