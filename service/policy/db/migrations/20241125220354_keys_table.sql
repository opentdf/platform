-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS
    public_keys (
        id uuid DEFAULT gen_random_uuid () PRIMARY KEY,
        is_active boolean NOT NULL DEFAULT TRUE,
        was_used boolean NOT NULL DEFAULT FALSE,
        key_access_server_id uuid NOT NULL REFERENCES key_access_servers (id),
        key_id varchar(36) NOT NULL,
        alg varchar(50) NOT NULL,
        public_key text NOT NULL,
        metadata jsonb,
        created_at timestamp,
        updated_at timestamp,
        UNIQUE (key_access_server_id, key_id, alg),
        CONSTRAINT unique_active_key EXCLUDE (
            key_access_server_id
            WITH
                =,
                alg
            WITH
                =
        )
        WHERE
            (is_active)
    );

CREATE
OR REPLACE FUNCTION update_active_key () RETURNS trigger AS $$
DECLARE
    current_active_key uuid;
BEGIN
    -- Look for existing active key for this KAS and algorithm
    SELECT id INTO current_active_key
    FROM public_keys
    WHERE key_access_server_id = NEW.key_access_server_id
        AND alg = NEW.alg
        AND is_active = TRUE;

    -- If no active key exists, mark the new one active
    IF current_active_key IS NULL THEN
        NEW.is_active = TRUE;
    -- If there is an active key and this is a new key, switch active status
    ELSIF current_active_key != NEW.id THEN
        UPDATE public_keys
        SET is_active = FALSE
        WHERE id = current_active_key;
        NEW.is_active = TRUE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER maintain_active_key BEFORE INSERT ON public_keys FOR EACH ROW
EXECUTE FUNCTION update_active_key ();

CREATE TABLE IF NOT EXISTS
    attribute_namespace_public_key_map (
        namespace_id uuid NOT NULL REFERENCES attribute_namespaces (id) ON DELETE CASCADE,
        key_id uuid NOT NULL REFERENCES public_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (namespace_id, key_id)
    );

CREATE TABLE IF NOT EXISTS
    attribute_definition_public_key_map (
        definition_id uuid NOT NULL REFERENCES attribute_definitions (id) ON DELETE CASCADE,
        key_id uuid NOT NULL REFERENCES public_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (definition_id, key_id)
    );

CREATE TABLE IF NOT EXISTS
    attribute_value_public_key_map (
        value_id uuid NOT NULL REFERENCES attribute_values (id) ON DELETE CASCADE,
        key_id uuid NOT NULL REFERENCES public_keys (id) ON DELETE CASCADE,
        PRIMARY KEY (value_id, key_id)
    );

-- Trigger function to update was_used column
CREATE
OR REPLACE FUNCTION update_was_used () RETURNS trigger AS $$
BEGIN
    UPDATE public_keys SET was_used = TRUE WHERE id = NEW.key_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for attribute_namespace_key_map
CREATE TRIGGER trigger_update_was_used_namespace
AFTER INSERT ON attribute_namespace_public_key_map FOR EACH ROW
EXECUTE FUNCTION update_was_used ();

-- View for active namespace keys
CREATE VIEW
    active_namespace_public_keys_view AS
SELECT
    km.namespace_id,
    jsonb_agg(
        DISTINCT jsonb_build_object(
            'id',
            ky.id,
            'is_active',
            ky.is_active,
            'was_used',
            ky.was_used,
            'public_key',
            json_build_object(
                'alg',
                ky.alg,
                'kid',
                ky.key_id,
                'pem',
                ky.public_key
            ),
            'kas',
            jsonb_build_object('id', kas.id, 'uri', kas.uri, 'name', kas.name)
        )
    ) AS keys
FROM
    public_keys AS ky
    INNER JOIN attribute_namespace_public_key_map AS km ON ky.id = km.key_id
    LEFT JOIN key_access_servers AS kas ON ky.key_access_server_id = kas.id
WHERE
    ky.is_active = TRUE
GROUP BY
    km.namespace_id;

-- Trigger for attribute_definition_key_map
CREATE TRIGGER trigger_update_was_used_definition
AFTER INSERT ON attribute_definition_public_key_map FOR EACH ROW
EXECUTE FUNCTION update_was_used ();

-- View for active definition keys
CREATE VIEW
    active_definition_public_keys_view AS
SELECT
    km.definition_id,
    jsonb_agg(
        DISTINCT jsonb_build_object(
            'id',
            ky.id,
            'is_active',
            ky.is_active,
            'was_used',
            ky.was_used,
            'public_key',
            json_build_object(
                'alg',
                ky.alg,
                'kid',
                ky.key_id,
                'pem',
                ky.public_key
            ),
            'kas',
            jsonb_build_object('id', kas.id, 'uri', kas.uri, 'name', kas.name)
        )
    ) AS keys
FROM
    public_keys AS ky
    INNER JOIN attribute_definition_public_key_map AS km ON ky.id = km.key_id
    LEFT JOIN key_access_servers AS kas ON ky.key_access_server_id = kas.id
WHERE
    ky.is_active = TRUE
GROUP BY
    km.definition_id;

-- Trigger for attribute_value_key_map
CREATE TRIGGER trigger_update_was_used_value
AFTER INSERT ON attribute_value_public_key_map FOR EACH ROW
EXECUTE FUNCTION update_was_used ();

-- View for active value keys
CREATE VIEW
    active_value_public_keys_view AS
SELECT
    km.value_id,
    jsonb_agg(
        DISTINCT jsonb_build_object(
            'id',
            ky.id,
            'is_active',
            ky.is_active,
            'was_used',
            ky.was_used,
            'public_key',
            json_build_object(
                'alg',
                ky.alg,
                'kid',
                ky.key_id,
                'pem',
                ky.public_key
            ),
            'kas',
            jsonb_build_object('id', kas.id, 'uri', kas.uri, 'name', kas.name)
        )
    ) AS keys
FROM
    public_keys AS ky
    INNER JOIN attribute_value_public_key_map AS km ON ky.id = km.key_id
    LEFT JOIN key_access_servers AS kas ON ky.key_access_server_id = kas.id
WHERE
    ky.is_active = TRUE
GROUP BY
    km.value_id;

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP VIEW IF EXISTS active_value_public_keys_view;

DROP VIEW IF EXISTS active_definition_public_keys_view;

DROP VIEW IF EXISTS active_namespace_public_keys_view;

DROP TRIGGER IF EXISTS trigger_update_was_used_namespace ON attribute_namespace_public_key_map;

DROP TRIGGER IF EXISTS trigger_update_was_used_definition ON attribute_definition_public_key_map;

DROP TRIGGER IF EXISTS trigger_update_was_used_value ON attribute_value_key_map;

DROP FUNCTION IF EXISTS update_was_used ();

DROP TABLE public_keys;

DROP TABLE attribute_namespace_public_key_map;

DROP TABLE attribute_definition_public_key_map;

DROP TABLE attribute_value_kpublic_key_map;

-- +goose StatementEnd