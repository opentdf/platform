-- +goose Up
-- +goose StatementBegin
ALTER TABLE key_access_servers
ADD COLUMN IF NOT EXISTS source_type INT;

CREATE TABLE IF NOT EXISTS
    asym_key (
        id UUID DEFAULT gen_random_uuid () PRIMARY KEY,
        key_id VARCHAR(36) NOT NULL, -- UNIQUE????
        key_alg INT NOT NULL,
        key_status INT NOT NULL,
        key_mode INT NOT NULL,
        -- key_access_server_id UUID NOT NULL REFERENCES key_access_servers (id),
        public_key bytea,
        private_key bytea,
        provider_config jsonb,
        metadata jsonb,
        created_at TIMESTAMP,
        updated_at TIMESTAMP
        -- CONSTRAINT unique_active_key EXCLUDE (
        --     key_access_server_id
        --     WITH
        --         =,
        --         alg
        --     WITH
        --         =
        -- )
        -- WHERE
        --     (is_active)
    );

COMMENT ON TABLE asym_key IS 'Table to store asymmetric keys';

COMMENT ON COLUMN asym_key.id IS 'Unique identifier for the key';

COMMENT ON COLUMN asym_key.key_status IS 'Indicates the status of the key Active, Inactive, Compromised, or Expired';

COMMENT ON COLUMN asym_key.key_mode IS 'Indicates whether the key is stored LOCAL or REMOTE';

COMMENT ON COLUMN asym_key.key_id IS 'Unique identifier for the key';

COMMENT ON COLUMN asym_key.key_alg IS 'Algorithm used to generate the key';

COMMENT ON COLUMN asym_key.public_key IS 'Public key in PEM or DER format';

COMMENT ON COLUMN asym_key.private_key IS 'Private key in PEM or DER format';

COMMENT ON COLUMN asym_key.provider_config IS 'This is extra configuration for the key provider';

COMMENT ON COLUMN asym_key.metadata IS 'Additional metadata for the key';

COMMENT ON COLUMN asym_key.created_at IS 'Timestamp when the key was created';

COMMENT ON COLUMN asym_key.updated_at IS 'Timestamp when the key was last updated';

CREATE TABLE IF NOT EXISTS
    sym_key (
        id UUID DEFAULT gen_random_uuid () PRIMARY KEY,
        key_id VARCHAR(36) NOT NULL,
        key_status INT NOT NULL,
        key_mode INT NOT NULL,
        key_value bytea,
        created_at TIMESTAMP,
        updated_at TIMESTAMP,
        metadata jsonb
    );

COMMENT ON TABLE sym_key IS 'Table to store symmetric keys';

COMMENT ON COLUMN sym_key.id IS 'Unique identifier for the key';

COMMENT ON COLUMN sym_key.key_id IS 'Unique identifier for the key';

COMMENT ON COLUMN sym_key.key_status IS 'Indicates the status of the key Active, Inactive, Compromised, or Expired';

COMMENT ON COLUMN sym_key.key_mode IS 'Indicates whether the key is stored LOCAL or REMOTE';

COMMENT ON COLUMN sym_key.key_value IS 'Key value in binary format';

COMMENT ON COLUMN sym_key.created_at IS 'Timestamp when the key was created';

COMMENT ON COLUMN sym_key.updated_at IS 'Timestamp when the key was last updated';

COMMENT ON COLUMN sym_key.metadata IS 'Additional metadata for the key';

CREATE TABLE IF NOT EXISTS
    key_access_server_keys (
        id UUID DEFAULT gen_random_uuid () PRIMARY KEY,
        key_access_server_id UUID NOT NULL REFERENCES key_access_servers (id) ON DELETE CASCADE,
        UNIQUE (key_access_server_id, key_id, key_alg) -- Prevents duplicate public keys for the same KAS by key_id and alg
    ) INHERITS (asym_key);

-- CREATE
-- OR REPLACE FUNCTION update_active_key () RETURNS TRIGGER AS $$
-- DECLARE
--     current_active_key uuid;
--     mapping_count int;
-- BEGIN
--     -- Log the incoming values
--     RAISE NOTICE 'New key ID: %, KAS ID: %, ALG: %', NEW.id, NEW.key_access_server_id, NEW.alg;
--     -- Look for existing active key for this KAS and algorithm
--     SELECT id INTO current_active_key
--     FROM public_keys
--     WHERE key_access_server_id = NEW.key_access_server_id
--         AND alg = NEW.alg
--         AND is_active = TRUE;
--     -- If no active key exists, mark the new one active
--     IF current_active_key IS NULL THEN
--         UPDATE public_keys SET is_active = TRUE WHERE id = NEW.id;
--         RAISE NOTICE 'No active key found, marking new key active';
--     -- If there is an active key and this is a new key, switch active status
--     ELSIF current_active_key != NEW.id THEN
--         BEGIN
--             RAISE NOTICE 'Copying mappings from key % to key %', current_active_key, NEW.id;
--             -- Copy namespace mappings
--             GET DIAGNOSTICS mapping_count = ROW_COUNT;
--             INSERT INTO attribute_namespace_public_key_map (namespace_id, key_id)
--             SELECT namespace_id, NEW.id
--             FROM attribute_namespace_public_key_map
--             WHERE key_id = current_active_key;
--             RAISE NOTICE 'Copied % namespace mappings', mapping_count;
--             -- Copy definition mappings
--             GET DIAGNOSTICS mapping_count = ROW_COUNT;
--             INSERT INTO attribute_definition_public_key_map (definition_id, key_id)
--             SELECT definition_id, NEW.id
--             FROM attribute_definition_public_key_map
--             WHERE key_id = current_active_key;
--             RAISE NOTICE 'Copied % definition mappings', mapping_count;
--             -- Copy value mappings
--             GET DIAGNOSTICS mapping_count = ROW_COUNT;
--             INSERT INTO attribute_value_public_key_map (value_id, key_id)
--             SELECT value_id, NEW.id
--             FROM attribute_value_public_key_map
--             WHERE key_id = current_active_key;
--             RAISE NOTICE 'Copied % value mappings', mapping_count;
--             UPDATE public_keys SET is_active = FALSE WHERE id = current_active_key;
--             UPDATE public_keys SET is_active = TRUE WHERE id = NEW.id;
--         EXCEPTION WHEN OTHERS THEN
--             RAISE NOTICE 'Error updating active key: %', SQLERRM;
--             -- Still deactivate the current active key
--             UPDATE public_keys SET is_active = FALSE WHERE id = current_active_key;
--             UPDATE public_keys SET is_active = TRUE WHERE id = NEW.id;
--         END;
--     END IF;
--     RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;
-- COMMENT ON FUNCTION update_active_key IS 'Function to update active key when a new key is inserted with the same algorithm and key_access_server_id';
-- CREATE TRIGGER maintain_active_key
-- AFTER INSERT ON public_keys FOR EACH ROW
-- EXECUTE FUNCTION update_active_key ();
CREATE TABLE IF NOT EXISTS
    attribute_namespace_public_key_map (
        namespace_id UUID NOT NULL REFERENCES attribute_namespaces (id) ON DELETE CASCADE,
        key_access_server_key_id UUID NOT NULL REFERENCES key_access_server_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (namespace_id, key_access_server_key_id)
    );

COMMENT ON TABLE attribute_namespace_public_key_map IS 'Table to map public keys to attribute namespaces';

COMMENT ON COLUMN attribute_namespace_public_key_map.namespace_id IS 'Foreign key to the attribute namespace';

COMMENT ON COLUMN attribute_namespace_public_key_map.key_access_server_key_id IS 'Foreign key to the key access server public key for wrapping symmetric keys';

CREATE TABLE IF NOT EXISTS
    attribute_definition_public_key_map (
        definition_id UUID NOT NULL REFERENCES attribute_definitions (id) ON DELETE CASCADE,
        key_access_server_key_id UUID NOT NULL REFERENCES key_access_server_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (definition_id, key_access_server_key_id)
    );

COMMENT ON TABLE attribute_definition_public_key_map IS 'Table to map public keys to attribute definitions';

COMMENT ON COLUMN attribute_definition_public_key_map.definition_id IS 'Foreign key to the attribute definition';

COMMENT ON COLUMN attribute_definition_public_key_map.key_access_server_key_id IS 'Foreign key to the key access server public key for wrapping symmetric keys';

CREATE TABLE IF NOT EXISTS
    attribute_value_public_key_map (
        value_id UUID NOT NULL REFERENCES attribute_values (id) ON DELETE CASCADE,
        key_access_server_key_id UUID NOT NULL REFERENCES key_access_server_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (value_id, key_access_server_key_id)
    );

COMMENT ON TABLE attribute_value_public_key_map IS 'Table to map public keys to attribute values';

COMMENT ON COLUMN attribute_value_public_key_map.value_id IS 'Foreign key to the attribute value';

COMMENT ON COLUMN attribute_value_public_key_map.key_access_server_key_id IS 'Foreign key to the key access server public key for wrapping symmetric keys';

-- -- Trigger function to update was_mapped column
-- CREATE
-- OR REPLACE FUNCTION update_was_mapped () RETURNS TRIGGER AS $$
-- BEGIN
--     UPDATE public_keys SET was_mapped = TRUE WHERE id = NEW.key_id;
--     RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;
-- COMMENT ON FUNCTION update_was_mapped IS 'Function to update was_mapped column when a key is mapped to a namespace, definition, or value';
-- -- Trigger for attribute_namespace_key_map
-- CREATE TRIGGER trigger_update_was_mapped_namespace
-- AFTER INSERT ON attribute_namespace_public_key_map FOR EACH ROW
-- EXECUTE FUNCTION update_was_mapped ();
-- View for active namespace keys
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
                'key_alg',
                ky.key_alg,
                'key_id',
                ky.key_id,
                'pem',
                ky.public_key
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

-- -- Trigger for attribute_definition_key_map
-- CREATE TRIGGER trigger_update_was_mapped_definition
-- AFTER INSERT ON attribute_definition_public_key_map FOR EACH ROW
-- EXECUTE FUNCTION update_was_mapped ();
-- View for active definition keys
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
                'key_alg',
                ky.key_alg,
                'key_id',
                ky.key_id,
                'pem',
                ky.public_key
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

-- -- Trigger for attribute_value_key_map
-- CREATE TRIGGER trigger_update_was_mapped_value
-- AFTER INSERT ON attribute_value_public_key_map FOR EACH ROW
-- EXECUTE FUNCTION update_was_mapped ();
-- View for active value keys
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
                'key_alg',
                ky.key_alg,
                'key_id',
                ky.key_id,
                'pem',
                ky.public_key
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

-- DROP TRIGGER IF EXISTS trigger_update_was_mapped_namespace ON attribute_namespace_public_key_map;
-- DROP TRIGGER IF EXISTS trigger_update_was_mapped_definition ON attribute_definition_public_key_map;
-- DROP TRIGGER IF EXISTS trigger_update_was_mapped_value ON attribute_value_key_map;
-- DROP TRIGGER IF EXISTS maintain_active_key;
-- DROP FUNCTION IF EXISTS update_active_key;
-- DROP FUNCTION IF EXISTS update_was_mapped ();
DROP TABLE IF EXISTS attribute_namespace_public_key_map;

DROP TABLE IF EXISTS attribute_definition_public_key_map;

DROP TABLE IF EXISTS attribute_value_public_key_map;

DROP TABLE IF EXISTS key_access_server_keys;

DROP TABLE IF EXISTS asym_key;

DROP TABLE IF EXISTS sym_key;

-- +goose StatementEnd