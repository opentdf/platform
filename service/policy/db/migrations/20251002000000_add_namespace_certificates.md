# Add Namespace Certificates

## Migration: 20251002000000_add_namespace_certificates.sql

### Purpose

This migration adds support for associating root certificates with attribute namespaces to establish a chain of trust for the OpenTDF platform.

### Changes

#### New Tables

1. **`certificates`** - Stores root certificate data
   - `id` (UUID, PRIMARY KEY) - Unique identifier for the certificate
   - `x5c` (TEXT, NOT NULL) - Base64-encoded DER certificate in x5c format
   - `metadata` (JSONB) - Optional metadata for the certificate (labels, etc.)
   - `created_at` (TIMESTAMP) - Creation timestamp
   - `updated_at` (TIMESTAMP) - Last update timestamp

2. **`attribute_namespace_certificates`** - Junction table for many-to-many relationship
   - `namespace_id` (UUID, FK to attribute_namespaces) - Reference to the namespace
   - `certificate_id` (UUID, FK to certificates) - Reference to the certificate
   - Composite PRIMARY KEY on (namespace_id, certificate_id)
   - CASCADE deletion on both foreign keys

#### Indexes

- Primary key index on `certificates(id)`
- Composite primary key index on `attribute_namespace_certificates(namespace_id, certificate_id)`
- Foreign key indexes created automatically by PostgreSQL

### Motivation

Root certificates need to be associated with namespaces to:
1. Establish chain of trust for attribute-based access control
2. Support certificate validation in the policy enforcement flow
3. Enable namespace-scoped trust boundaries

The junction table design allows:
- Multiple certificates per namespace (certificate rotation/migration scenarios)
- Certificate reuse across namespaces (if needed)
- Clean cascade deletion when namespaces or certificates are removed

### Certificate Format

Certificates are stored in **x5c format**: base64-encoded DER (Distinguished Encoding Rules) representation without PEM headers/footers, following the JWT/JWS standard (RFC 7515 Section 4.1.6).

### Schema Relations

```
attribute_namespaces (1) ----< (N) attribute_namespace_certificates (N) >---- (1) certificates
```

- One namespace can have many certificates (one-to-many)
- One certificate can be assigned to many namespaces (many-to-one, though typically one-to-one)
- Junction table enables many-to-many flexibility

### Backward Compatibility

This migration is **non-breaking**:
- Only adds new tables, does not modify existing tables
- No data migration required
- Existing functionality continues to work unchanged
- New certificate fields (`root_certs`) in Namespace proto are optional

### Testing

Before merging, verify:
- [x] Migration up succeeds
- [x] Migration down succeeds and removes tables cleanly
- [x] CRUD operations on certificates work correctly
- [x] Foreign key constraints enforce referential integrity
- [x] CASCADE deletion works as expected
- [x] Schema ERD updated with new relations
