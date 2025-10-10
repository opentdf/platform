-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS certificates
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pem TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE certificates IS 'Table to store X.509 certificates for chain of trust (root only)';
COMMENT ON COLUMN certificates.id IS 'Unique identifier for the certificate';
COMMENT ON COLUMN certificates.pem IS 'PEM format - Base64-encoded DER certificate (not PEM; no headers/footers)';
COMMENT ON COLUMN certificates.metadata IS 'Optional metadata for the certificate';
COMMENT ON COLUMN certificates.created_at IS 'Timestamp when the certificate was created';
COMMENT ON COLUMN certificates.updated_at IS 'Timestamp when the certificate was last updated';

CREATE TABLE IF NOT EXISTS attribute_namespace_certificates
(
    namespace_id UUID NOT NULL REFERENCES attribute_namespaces(id) ON DELETE CASCADE,
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    PRIMARY KEY (namespace_id, certificate_id)
);

COMMENT ON TABLE attribute_namespace_certificates IS 'Junction table to map root certificates to attribute namespaces';
COMMENT ON COLUMN attribute_namespace_certificates.namespace_id IS 'Foreign key to the namespace';
COMMENT ON COLUMN attribute_namespace_certificates.certificate_id IS 'Foreign key to the certificate';

CREATE TRIGGER certificates_updated_at
  BEFORE UPDATE ON certificates
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS certificates_updated_at ON certificates;
DROP TABLE IF EXISTS attribute_namespace_certificates;
DROP TABLE IF EXISTS certificates;

-- +goose StatementEnd
