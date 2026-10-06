-- +goose Up
-- +goose StatementBegin

DO $$
DECLARE
    namespace_view TEXT := pg_get_viewdef('active_namespace_public_keys_view'::regclass, true);
    definition_view TEXT := pg_get_viewdef('active_definition_public_keys_view'::regclass, true);
    value_view TEXT := pg_get_viewdef('active_value_public_keys_view'::regclass, true);
BEGIN
    -- PostgreSQL requires dependent views to be recreated when the column type changes.
    DROP VIEW active_namespace_public_keys_view;
    DROP VIEW active_definition_public_keys_view;
    DROP VIEW active_value_public_keys_view;

    -- Changes to asym_key also apply to its child table key_access_server_keys.
    ALTER TABLE asym_key ALTER COLUMN key_id TYPE TEXT;

    -- Enforce bytes without VARCHAR's character counting or trailing-space truncation.
    ALTER TABLE asym_key ADD CONSTRAINT asym_key_key_id_max_bytes
        CHECK (octet_length(key_id) <= 128);

    EXECUTE 'CREATE VIEW active_namespace_public_keys_view AS ' || namespace_view;
    COMMENT ON VIEW active_namespace_public_keys_view IS 'View to retrieve active public keys mapped to attribute namespaces';
    EXECUTE 'CREATE VIEW active_definition_public_keys_view AS ' || definition_view;
    COMMENT ON VIEW active_definition_public_keys_view IS 'View to retrieve active public keys mapped to attribute definitions';
    EXECUTE 'CREATE VIEW active_value_public_keys_view AS ' || value_view;
    COMMENT ON VIEW active_value_public_keys_view IS 'View to retrieve active public keys mapped to attribute values';
END;
$$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DO $$
DECLARE
    namespace_view TEXT := pg_get_viewdef('active_namespace_public_keys_view'::regclass, true);
    definition_view TEXT := pg_get_viewdef('active_definition_public_keys_view'::regclass, true);
    value_view TEXT := pg_get_viewdef('active_value_public_keys_view'::regclass, true);
BEGIN
    IF EXISTS (SELECT 1 FROM asym_key WHERE char_length(key_id) > 36) THEN
        RAISE EXCEPTION 'Cannot restore the 36-character KID limit while longer key IDs exist';
    END IF;

    -- PostgreSQL requires dependent views to be recreated when the column type changes.
    DROP VIEW active_namespace_public_keys_view;
    DROP VIEW active_definition_public_keys_view;
    DROP VIEW active_value_public_keys_view;

    ALTER TABLE asym_key DROP CONSTRAINT asym_key_key_id_max_bytes;
    -- Refuse rollback when longer IDs exist rather than truncating them.
    ALTER TABLE asym_key ALTER COLUMN key_id TYPE VARCHAR(36);

    EXECUTE 'CREATE VIEW active_namespace_public_keys_view AS ' || namespace_view;
    COMMENT ON VIEW active_namespace_public_keys_view IS 'View to retrieve active public keys mapped to attribute namespaces';
    EXECUTE 'CREATE VIEW active_definition_public_keys_view AS ' || definition_view;
    COMMENT ON VIEW active_definition_public_keys_view IS 'View to retrieve active public keys mapped to attribute definitions';
    EXECUTE 'CREATE VIEW active_value_public_keys_view AS ' || value_view;
    COMMENT ON VIEW active_value_public_keys_view IS 'View to retrieve active public keys mapped to attribute values';
END;
$$;

-- +goose StatementEnd
