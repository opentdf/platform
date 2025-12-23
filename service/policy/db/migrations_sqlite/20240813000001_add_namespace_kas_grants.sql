-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS attribute_namespace_key_access_grants
(
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    key_access_server_id TEXT NOT NULL REFERENCES key_access_servers(id) ON DELETE CASCADE,
    PRIMARY KEY (namespace_id, key_access_server_id)
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Store grants of key access servers (KASs) to attribute namespaces
-- namespace_id: Foreign key to the namespace of the KAS grant
-- key_access_server_id: Foreign key to the KAS registration

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS attribute_namespace_key_access_grants;

-- +goose StatementEnd
