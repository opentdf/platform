-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS certificates
(
    id TEXT PRIMARY KEY,
    pem TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Store X.509 certificates for chain of trust (root only)
-- id: Unique identifier for the certificate
-- pem: PEM format - Base64-encoded DER certificate
-- metadata: Optional metadata for the certificate

CREATE TABLE IF NOT EXISTS attribute_namespace_certificates
(
    namespace_id TEXT NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    certificate_id TEXT NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    PRIMARY KEY (namespace_id, certificate_id)
);

-- SQLite: Comments documented here instead of COMMENT ON
-- Table: Junction table to map root certificates to attribute namespaces
-- namespace_id: Foreign key to the namespace
-- certificate_id: Foreign key to the certificate

-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER certificates_updated_at
AFTER UPDATE ON certificates
FOR EACH ROW
BEGIN
    UPDATE certificates SET updated_at = datetime('now') WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS certificates_updated_at;
DROP TABLE IF EXISTS attribute_namespace_certificates;
DROP TABLE IF EXISTS certificates;

-- +goose StatementEnd
