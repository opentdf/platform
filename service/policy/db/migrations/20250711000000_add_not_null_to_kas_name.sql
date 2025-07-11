-- +goose Up
-- +goose StatementBegin

DO $$
DECLARE
    kas_row RECORD;
BEGIN
    FOR kas_row IN SELECT id, uri, name FROM key_access_servers WHERE name IS NULL LOOP
        RAISE NOTICE 'key_access_server with id % has NULL name, copying from uri (%)', kas_row.id, kas_row.uri;
        UPDATE key_access_servers SET name = kas_row.uri WHERE id = kas_row.id;
    END LOOP;
END $$;

ALTER TABLE key_access_servers ALTER COLUMN name SET NOT NULL;
COMMENT ON COLUMN key_access_servers.name IS 'Unique common name of the KAS';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

COMMENT ON COLUMN key_access_servers.name IS 'Optional common name of the KAS';
ALTER TABLE key_access_servers ALTER COLUMN name DROP NOT NULL;

-- +goose StatementEnd
