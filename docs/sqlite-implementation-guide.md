# SQLite Implementation Guide

This document describes SQLite support as a drop-in replacement for PostgreSQL in the OpenTDF platform.

## Quick Start

### Running with SQLite

**Integration Tests (no Docker required):**
```bash
# Run integration tests with SQLite
make integration-test-sqlite

# Or directly:
OPENTDF_TEST_DB=sqlite go test ./service/integration/... -v
```

**Configuration:**
```yaml
db:
  driver: sqlite          # "postgres" (default) or "sqlite"
  sqlitePath: ":memory:"  # File path or ":memory:" for in-memory
```

**Programmatic:**
```go
import "github.com/opentdf/platform/service/pkg/db"

cfg := db.Config{
    Driver:     db.DriverSQLite,
    SQLitePath: "./opentdf.db",  // or ":memory:"
}
client, err := db.New(ctx, cfg, logCfg, &tracer)
```

### Makefile Targets

```bash
# Integration tests with SQLite (no Docker required)
make integration-test-sqlite

# Integration tests with PostgreSQL (requires Docker)
make integration-test

# Run both database backends
make integration-test-all
```

---

## Known Limitations

SQLite has full feature parity with PostgreSQL for the OpenTDF platform, with these caveats:

| Feature | PostgreSQL | SQLite | Notes |
|---------|------------|--------|-------|
| Concurrent writes | Full MVCC | Single-writer (WAL mode) | SQLite queues writes |
| Connection pooling | Unlimited | Limited by file locks | Use `MaxOpenConns: 1` for writes |
| JSON functions | Native JSONB | json1 extension | Requires SQLite 3.38+ |
| Full-text search | `tsvector`/`tsquery` | Not implemented | Use external library if needed |
| GIN indexes | Native | Not available | Standard indexes used instead |

**Trigger Emulation:** Complex PostgreSQL triggers (key rotation, cascade deactivation) are implemented in Go in `triggers_emulation.go` rather than as database triggers.

---

## Architecture Overview

SQLite support is implemented through:

| Component | Location | Description |
|-----------|----------|-------------|
| Driver abstraction | `service/pkg/db/driver.go` | `DriverType` enum and interface |
| SQLite driver | `service/pkg/db/driver_sqlite.go` | SQLite connection with WAL, foreign keys |
| PostgreSQL driver | `service/pkg/db/driver_postgres.go` | Wraps existing pgx pool |
| Query router | `service/policy/db/query_router.go` | Routes queries to correct driver |
| SQLite migrations | `service/policy/db/migrations_sqlite/` | 38 SQLite-compatible migrations |
| SQLite queries | `service/policy/db/queries_sqlite/` | 11 SQLite query files for sqlc |
| Trigger emulation | `service/policy/db/triggers_emulation.go` | Go implementation of PL/pgSQL triggers |
| Constraint emulation | `service/policy/db/constraints_sqlite.go` | EXCLUDE constraint validation |
| Bulk insert | `service/policy/db/bulk_insert.go` | Replaces PostgreSQL COPY protocol |
| Error mapping | `service/pkg/db/errors_sqlite.go` | SQLite error code mapping |

---

## Implementation Details

The original PostgreSQL implementation uses:

### File Inventory

| Directory | File Count | Description |
|-----------|------------|-------------|
| `service/pkg/db/` | 6 files | Core database abstraction |
| `service/policy/db/` | 31 Go files | Policy data access layer |
| `service/policy/db/queries/` | 11 SQL files | sqlc query definitions |
| `service/policy/db/migrations/` | 38 SQL files | Goose migrations |

---

## Phase 1: Database Abstraction Layer

### 1.1 Create Driver-Agnostic Connection Interface

**File:** `service/pkg/db/db.go`

The current `PgxIface` interface is tightly coupled to pgx:

```go
type PgxIface interface {
    Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
    Query(context.Context, string, ...any) (pgx.Rows, error)
    QueryRow(context.Context, string, ...any) pgx.Row
    Begin(context.Context) (pgx.Tx, error)
    CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
    // ...
}
```

**Required Changes:**
1. Create a new generic `DBInterface` that abstracts away driver-specific types
2. Use `database/sql` types as the common denominator (`sql.Result`, `sql.Rows`, `sql.Row`)
3. Create wrapper implementations for both pgx and SQLite drivers

```go
// Proposed abstraction
type DBDriver interface {
    Exec(ctx context.Context, query string, args ...any) (sql.Result, error)
    Query(ctx context.Context, query string, args ...any) (*sql.Rows, error)
    QueryRow(ctx context.Context, query string, args ...any) *sql.Row
    BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
    Close() error
}
```

### 1.2 Create Driver Factory

**New File:** `service/pkg/db/driver.go`

```go
type DriverType string

const (
    DriverPostgres DriverType = "postgres"
    DriverSQLite   DriverType = "sqlite"
)

func NewConnection(ctx context.Context, cfg Config) (DBDriver, error) {
    switch cfg.Driver {
    case DriverPostgres:
        return newPostgresConnection(ctx, cfg)
    case DriverSQLite:
        return newSQLiteConnection(ctx, cfg)
    default:
        return nil, fmt.Errorf("unsupported driver: %s", cfg.Driver)
    }
}
```

### 1.3 Update Configuration

**File:** `service/pkg/db/config.go`

Add driver selection to the configuration:

```go
type Config struct {
    Driver          DriverType // NEW: "postgres" or "sqlite"
    Host            string     // Postgres only
    Port            int        // Postgres only
    Database        string     // Database name or file path for SQLite
    // ... existing fields
}
```

---

## Phase 2: Query Builder Modifications

### 2.1 Squirrel Placeholder Format

**File:** `service/pkg/db/db.go:308-310`

Current implementation uses PostgreSQL `$` placeholders:

```go
func NewStatementBuilder() sq.StatementBuilderType {
    return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}
```

**Required Changes:**

```go
func NewStatementBuilder(driver DriverType) sq.StatementBuilderType {
    switch driver {
    case DriverSQLite:
        return sq.StatementBuilder.PlaceholderFormat(sq.Question)
    default:
        return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
    }
}
```

### 2.2 sqlc Configuration

**File:** `service/policy/db/sqlc.yaml`

Current sqlc is configured for PostgreSQL. Options:

**Option A: Dual Engine Configuration**
```yaml
version: "2"
sql:
  - engine: "postgresql"
    queries: "queries/"
    schema: "migrations/"
    gen:
      go:
        package: "db"
        out: "."
  - engine: "sqlite"
    queries: "queries_sqlite/"  # Duplicated queries
    schema: "migrations_sqlite/"
    gen:
      go:
        package: "db_sqlite"
        out: "./sqlite"
```

**Option B: Raw SQL with Manual Type Mapping**
- Move away from sqlc for generated code
- Use Squirrel for all query building
- Manual parameter binding and result scanning

**Recommendation:** Option B is cleaner long-term but requires significant refactoring of the generated code in `service/policy/db/*.sql.go`.

---

## Phase 3: SQL Migration Rewrites

### 3.1 PostgreSQL Features Requiring Alternatives

The 38 migration files use these PostgreSQL-specific features:

| PostgreSQL Feature | SQLite Alternative | Occurrences | Affected Locations |
|--------------------|-------------------|-------------|---------------------|
| `UUID` type | `TEXT` with application-generated UUIDs | All tables | All migrations |
| `gen_random_uuid()` | Generate UUID in application layer | 28 occurrences | 15 migration files |
| `JSONB` | `TEXT` with JSON validation or `JSON` (SQLite 3.38+) | 66 occurrences | 16 migration files |
| `VARCHAR[]`, `UUID[]`, `TEXT[]` | Junction tables or JSON arrays | 6 columns | 20240131, 20240305, 20240813, 20250527 |
| `ENUM` types | `TEXT` with CHECK constraints | 1 type | 20240212 (attribute_definition_rule) |
| `TIMESTAMP WITH TIME ZONE` | `TEXT` (ISO8601) or `INTEGER` (Unix) | All tables | All migrations |
| PL/pgSQL triggers | Application-layer logic or simple triggers | 30 triggers | See trigger breakdown below |
| `JSONB_AGG()`, `JSON_BUILD_OBJECT()` | `json_group_array()`, `json_object()` | 479 occurrences | 24 files (queries + migrations) |
| `EXCLUDE` constraints | Application-layer validation | 1 constraint | 20241125 (unique_active_key) |
| `UNIQUE NULLS NOT DISTINCT` | Partial indexes or application logic | 1 constraint | 20240213 (attribute_fqn) |
| `GIN` indexes | Standard indexes (limited JSONB support) | 1 index | 20250527 (selector_values) |
| Window functions `COUNT(*) OVER()` | Subqueries or application layer | 27 occurrences | 12 files |
| `ON CONFLICT DO NOTHING` | `INSERT OR IGNORE` | Multiple | Various migrations |
| Regex `!~` operator | `GLOB` or `LIKE` patterns | 1 occurrence | 20250411 validation |

### 3.2 Trigger Breakdown

The 30 triggers fall into these categories:

| Category | Count | Complexity | SQLite Strategy |
|----------|-------|------------|-----------------|
| `updated_at` timestamp | 15 | Low | Simple SQLite triggers |
| Cascade deactivation | 2 | Medium | Multiple simple triggers per relationship |
| Key rotation (`update_active_key`) | 1 | **Very High** | Application-layer Go function |
| Key mapping (`was_mapped_*`) | 3 | High | Application-layer logic |
| Value order preservation | 2 | Medium | Application-layer logic |
| Selector extraction | 1 | High | Pre-compute in application |
| Base key validation | 1 | Medium | CHECK constraints + app logic |
| Other business logic | 5 | Medium | Case-by-case evaluation |

### 3.3 Migration File Strategy

**Option A: Parallel Migration Sets (Recommended)**

Create SQLite-specific migrations in a separate directory:
```
service/policy/db/
├── migrations/           # PostgreSQL migrations
└── migrations_sqlite/    # SQLite migrations
```

**Option B: Conditional SQL in Migrations**

Use Goose's Go-based migrations for complex operations:
```go
// migrations/20240212000000_initial.go
func Up(ctx context.Context, tx *sql.Tx) error {
    driver := getDriverFromContext(ctx)
    if driver == "sqlite" {
        _, err := tx.ExecContext(ctx, sqliteSchema)
    } else {
        _, err := tx.ExecContext(ctx, postgresSchema)
    }
    return err
}
```

### 3.4 Specific Migration Conversions

#### Migration 20240212 (Initial Schema)

**PostgreSQL:**
```sql
CREATE TYPE attribute_definition_rule AS ENUM (
    'UNSPECIFIED', 'ALL_OF', 'ANY_OF', 'HIERARCHY'
);

CREATE TABLE attribute_namespaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(253) NOT NULL UNIQUE,
    active BOOLEAN DEFAULT TRUE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

**SQLite Equivalent:**
```sql
CREATE TABLE attribute_namespaces (
    id TEXT PRIMARY KEY,  -- UUID generated by application
    name TEXT NOT NULL UNIQUE CHECK(LENGTH(name) <= 253),
    active INTEGER DEFAULT 1,  -- Boolean as 0/1
    metadata TEXT,  -- JSON stored as TEXT
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Enum simulation via CHECK constraint
CREATE TABLE attribute_definitions (
    -- ...
    rule TEXT NOT NULL CHECK(rule IN ('UNSPECIFIED', 'ALL_OF', 'ANY_OF', 'HIERARCHY')),
    -- ...
);
```

#### Migration 20240212 (Cascade Trigger)

**PostgreSQL PL/pgSQL:**
```sql
CREATE FUNCTION cascade_deactivation() RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'UPDATE' AND NEW.active = false) THEN
        EXECUTE format('UPDATE %I.%I SET active = $1 WHERE %s = $2', ...)
        USING NEW.active, OLD.id;
    END IF;
    RETURN NULL;
END $$ LANGUAGE 'plpgsql';
```

**SQLite Alternative:**
```sql
-- Simple trigger for each table relationship
CREATE TRIGGER cascade_deactivate_definitions
AFTER UPDATE OF active ON attribute_namespaces
WHEN NEW.active = 0
BEGIN
    UPDATE attribute_definitions SET active = 0 WHERE namespace_id = OLD.id;
END;

CREATE TRIGGER cascade_deactivate_values
AFTER UPDATE OF active ON attribute_definitions
WHEN NEW.active = 0
BEGIN
    UPDATE attribute_values SET active = 0 WHERE attribute_definition_id = OLD.id;
END;
```

#### Migration 20241125 (Key Rotation Trigger - 324 lines)

This complex trigger handles key rotation with mapping copies.

**SQLite Alternative:** Move logic to application layer in `service/policy/db/public_keys.go`:

```go
func (c *PolicyDBClient) InsertPublicKey(ctx context.Context, key PublicKey) error {
    tx, err := c.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    // 1. Insert new key
    // 2. If key should be active, deactivate existing active key
    // 3. Copy mappings from old active key to new key
    // 4. Commit transaction

    return tx.Commit()
}
```

#### Migration 20240213 (UNIQUE NULLS NOT DISTINCT)

**PostgreSQL (15+ feature):**
```sql
CREATE TABLE attribute_fqns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL,
    attribute_id UUID,
    value_id UUID,
    fqn TEXT NOT NULL UNIQUE,
    UNIQUE NULLS NOT DISTINCT (namespace_id, attribute_id, value_id)
);
```

This constraint treats NULL values as equal for uniqueness purposes.

**SQLite Alternative:** Use a partial unique index + a separate index for NULL cases:

```sql
CREATE TABLE attribute_fqns (
    id TEXT PRIMARY KEY,
    namespace_id TEXT NOT NULL,
    attribute_id TEXT,
    value_id TEXT,
    fqn TEXT NOT NULL UNIQUE
);

-- Unique when all are non-null
CREATE UNIQUE INDEX idx_fqns_all_non_null
ON attribute_fqns(namespace_id, attribute_id, value_id)
WHERE attribute_id IS NOT NULL AND value_id IS NOT NULL;

-- Unique when attribute_id is null
CREATE UNIQUE INDEX idx_fqns_attr_null
ON attribute_fqns(namespace_id)
WHERE attribute_id IS NULL AND value_id IS NULL;

-- Unique when value_id is null but attribute_id is not
CREATE UNIQUE INDEX idx_fqns_value_null
ON attribute_fqns(namespace_id, attribute_id)
WHERE attribute_id IS NOT NULL AND value_id IS NULL;
```

**Note:** This requires careful analysis of the actual NULL combinations allowed by the business logic.

---

## Phase 4: Error Handling

### 4.1 Update Error Mapping

**File:** `service/pkg/db/errors.go`

Current implementation maps PostgreSQL error codes:

```go
func WrapIfKnownInvalidQueryErr(err error) error {
    var pgErr *pgconn.PgError
    if errors.As(err, &pgErr) {
        switch pgErr.Code {
        case pgerrcode.UniqueViolation:
            return ErrUniqueConstraintViolation
        // ...
        }
    }
}
```

**Required Changes:**

```go
func WrapIfKnownInvalidQueryErr(err error) error {
    // PostgreSQL error handling
    var pgErr *pgconn.PgError
    if errors.As(err, &pgErr) {
        return mapPostgresError(pgErr)
    }

    // SQLite error handling
    if sqliteErr, ok := err.(sqlite3.Error); ok {
        return mapSQLiteError(sqliteErr)
    }

    return err
}

func mapSQLiteError(err sqlite3.Error) error {
    switch err.ExtendedCode {
    case sqlite3.ErrConstraintUnique:
        return ErrUniqueConstraintViolation
    case sqlite3.ErrConstraintNotNull:
        return ErrNotNullViolation
    case sqlite3.ErrConstraintForeignKey:
        return ErrForeignKeyViolation
    case sqlite3.ErrConstraintCheck:
        return ErrCheckViolation
    default:
        return err
    }
}
```

---

## Phase 5: Bulk Insert Operations

### 5.1 Replace COPY Protocol

**File:** `service/policy/db/copyfrom.go`

PostgreSQL's COPY protocol is used for bulk inserts:

```go
func (q *Queries) createRegisteredResourceActionAttributeValues(
    ctx context.Context,
    arg []createRegisteredResourceActionAttributeValuesParams,
) (int64, error) {
    return q.db.CopyFrom(ctx, tableName, columns, &iterator{rows: arg})
}
```

**SQLite Alternative:** Batch inserts within a transaction:

```go
func (q *Queries) createRegisteredResourceActionAttributeValuesSQLite(
    ctx context.Context,
    arg []createRegisteredResourceActionAttributeValuesParams,
) (int64, error) {
    tx, err := q.db.BeginTx(ctx, nil)
    if err != nil {
        return 0, err
    }
    defer tx.Rollback()

    stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO registered_resource_action_attribute_values
        (registered_resource_value_id, action_id, attribute_value_id)
        VALUES (?, ?, ?)
    `)
    if err != nil {
        return 0, err
    }
    defer stmt.Close()

    var count int64
    for _, row := range arg {
        _, err := stmt.ExecContext(ctx, row.ResourceValueID, row.ActionID, row.AttributeValueID)
        if err != nil {
            return count, err
        }
        count++
    }

    return count, tx.Commit()
}
```

---

## Phase 6: Query Rewrites

### 6.1 JSON Aggregation Functions

**PostgreSQL:**
```sql
SELECT
    ad.id,
    JSON_BUILD_OBJECT('labels', ad.metadata->'labels') as metadata,
    JSONB_AGG(DISTINCT jsonb_build_object('id', v.id, 'value', v.value)) as values
FROM attribute_definitions ad
LEFT JOIN attribute_values v ON v.attribute_definition_id = ad.id
GROUP BY ad.id
```

**SQLite Alternative:**
```sql
SELECT
    ad.id,
    json_object('labels', json_extract(ad.metadata, '$.labels')) as metadata,
    json_group_array(DISTINCT json_object('id', v.id, 'value', v.value)) as values
FROM attribute_definitions ad
LEFT JOIN attribute_values v ON v.attribute_definition_id = ad.id
GROUP BY ad.id
```

**Note:** SQLite's JSON functions require version 3.38.0+ (2022-02-22).

### 6.2 Window Functions for Pagination

**PostgreSQL:**
```sql
SELECT *, COUNT(*) OVER() as total
FROM attribute_definitions
LIMIT $1 OFFSET $2
```

**SQLite Alternative (if window functions unavailable):**
```sql
-- Two queries or subquery approach
SELECT *, (SELECT COUNT(*) FROM attribute_definitions) as total
FROM attribute_definitions
LIMIT ? OFFSET ?
```

### 6.3 Array Operations

**PostgreSQL:**
```sql
SELECT * FROM attribute_values
WHERE id = ANY($1::uuid[])
```

**SQLite Alternative:**
```sql
-- Generate placeholders dynamically in application
SELECT * FROM attribute_values
WHERE id IN (?, ?, ?, ...)
```

---

## Phase 7: Type Mapping

### 7.1 Data Type Conversions

| PostgreSQL Type | SQLite Type | Go Type Mapping |
|-----------------|-------------|-----------------|
| `UUID` | `TEXT` | `string` (validate format) |
| `BOOLEAN` | `INTEGER` | `int` (0/1) → `bool` |
| `JSONB` | `TEXT` | `string` → `json.RawMessage` |
| `TIMESTAMP WITH TIME ZONE` | `TEXT` | `string` (ISO8601) → `time.Time` |
| `VARCHAR(n)` | `TEXT` | `string` with CHECK constraint |
| `INTEGER` / `BIGINT` | `INTEGER` | `int64` |
| `TEXT[]` | `TEXT` (JSON array) | `[]string` via JSON marshal |
| `UUID[]` | `TEXT` (JSON array) | `[]string` via JSON marshal |
| Custom `ENUM` | `TEXT` | `string` with CHECK constraint |

### 7.2 pgtype.* Wrapper Replacement

**File:** `service/policy/db/models.go`

The sqlc-generated models use pgx-specific type wrappers:

```go
// Current PostgreSQL-specific types
type AttributeDefinition struct {
    ID          pgtype.UUID        // → string
    Name        string
    Rule        NullAttributeDefinitionRule
    Metadata    []byte             // JSONB
    NamespaceID pgtype.UUID        // → string
    Active      pgtype.Bool        // → *bool or sql.NullBool
    CreatedAt   pgtype.Timestamptz // → time.Time
    UpdatedAt   pgtype.Timestamptz // → time.Time
}
```

**Required Changes:**

Option A: Create type aliases that work for both drivers:
```go
// service/pkg/db/types.go
type UUID = string
type NullBool = sql.NullBool
type Timestamp = time.Time
```

Option B: Use sqlc overrides in configuration:
```yaml
# sqlc.yaml
overrides:
  - db_type: "uuid"
    go_type: "string"
  - db_type: "timestamptz"
    go_type: "time.Time"
  - db_type: "bool"
    go_type: "*bool"
    nullable: true
```

### 7.3 UUID Generation

**New utility:** `service/pkg/db/uuid.go`

```go
import "github.com/google/uuid"

func GenerateUUID() string {
    return uuid.New().String()
}

// For SQLite, generate UUIDs in application before INSERT
func (c *PolicyDBClient) CreateAttribute(ctx context.Context, attr *Attribute) error {
    if c.driver == DriverSQLite && attr.ID == "" {
        attr.ID = GenerateUUID()
    }
    // ... insert logic
}
```

---

## Phase 8: Testing Infrastructure

### 8.1 Integration Tests

Create SQLite-specific test fixtures:

```go
// service/pkg/db/db_test.go
func TestWithSQLite(t *testing.T) {
    db, err := NewConnection(context.Background(), Config{
        Driver:   DriverSQLite,
        Database: ":memory:",  // In-memory for tests
    })
    require.NoError(t, err)
    defer db.Close()

    // Run migrations
    err = RunMigrations(db, "migrations_sqlite")
    require.NoError(t, err)

    // Run test cases
}
```

### 8.2 CI Pipeline Updates

Add SQLite test matrix:

```yaml
# .github/workflows/test.yml
jobs:
  test:
    strategy:
      matrix:
        database: [postgres, sqlite]
    steps:
      - name: Run tests
        run: go test -tags=${{ matrix.database }} ./...
```

---

## Phase 9: Feature Parity Considerations

### 9.1 Features Requiring Application-Layer Handling

| Feature | PostgreSQL Behavior | SQLite Implementation |
|---------|---------------------|----------------------|
| Cascade deactivation | Trigger-based | Application-layer logic |
| Key rotation | 324-line PL/pgSQL function | Go function in `public_keys.go` |
| Selector extraction | Trigger with JSONB operations | Pre-compute on INSERT/UPDATE |
| Exclusion constraints | Database-enforced | Application validation |
| Full-text search | `tsvector`/`tsquery` | External library (Bleve) or LIKE |

### 9.2 Performance Considerations

1. **Connection pooling:** SQLite is single-writer; use `database/sql` pool with `MaxOpenConns: 1` for writes
2. **Write-Ahead Logging:** Enable WAL mode for concurrent reads:
   ```sql
   PRAGMA journal_mode=WAL;
   ```
3. **Foreign key enforcement:** Explicitly enable:
   ```sql
   PRAGMA foreign_keys=ON;
   ```
4. **Bulk inserts:** Use transactions to batch operations (vs. PostgreSQL COPY)

---

## Implementation Checklist

### Prerequisites
- [x] Evaluate if SQLite feature limitations are acceptable for use case
- [x] Decide on migration strategy (parallel migrations vs. conditional)
- [x] Plan for trigger logic migration (application layer)

### Core Changes
- [x] Create driver abstraction interface (`service/pkg/db/driver.go`)
- [x] Implement SQLite connection wrapper (`service/pkg/db/driver_sqlite.go`)
- [x] Update configuration to support driver selection
- [x] Modify Squirrel placeholder format based on driver
- [x] Create SQLite-specific error mapping (`service/pkg/db/errors_sqlite.go`)

### Migration Files (38 files)
- [x] Create `migrations_sqlite/` directory
- [x] Convert 38 migration files to SQLite syntax
- [x] Replace 28 `gen_random_uuid()` calls with application-layer UUID generation
- [x] Convert 66 JSONB column definitions to TEXT/JSON
- [x] Replace 6 array columns with JSON or junction tables
- [x] Rewrite 30 triggers (15 simple, 15 complex requiring app logic)
- [x] Convert ENUM type to CHECK constraint
- [x] Handle `UNIQUE NULLS NOT DISTINCT` with partial indexes (20240213)
- [x] Handle `EXCLUDE` constraint with application logic (20241125)

### Query Layer (11 query files, 11 generated .sql.go files)
- [x] Audit all 11 sqlc query files in `queries/` for PostgreSQL syntax
- [x] Create SQLite-compatible query files in `queries_sqlite/`
- [x] Rewrite 479 JSON aggregation function calls
- [x] Replace `JSON_BUILD_OBJECT` with `json_object`
- [x] Replace `JSONB_AGG` with `json_group_array`
- [x] Handle `ANY(array)` → `IN (...)` conversion
- [x] Replace COPY protocol with batch inserts (`service/policy/db/bulk_insert.go`)
- [x] Update `pgtype.*` usage in `models.go` to driver-agnostic types

### Testing
- [x] Create SQLite integration test suite
- [x] Add SQLite to CI test matrix (Makefile targets)
- [x] Validate data type conversions
- [ ] Performance benchmarks

### Documentation
- [x] Update deployment documentation
- [x] Document SQLite-specific configuration
- [x] Document feature limitations

---

## Implementation Summary

### Files Added

| Component | Files | Description |
|-----------|-------|-------------|
| Driver layer | 3 Go files | `driver.go`, `driver_sqlite.go`, `driver_postgres.go` |
| SQLite migrations | 38 SQL files | `migrations_sqlite/*.sql` |
| SQLite queries | 11 SQL files | `queries_sqlite/*.sql` |
| Query router | 1 Go file | `query_router.go` |
| Trigger emulation | 1 Go file | `triggers_emulation.go` |
| Constraint emulation | 1 Go file | `constraints_sqlite.go` |
| Bulk insert | 1 Go file | `bulk_insert.go` |
| Error handling | 1 Go file | `errors_sqlite.go` |

### Trigger Emulation Summary

| Trigger Type | Count | Implementation |
|--------------|-------|----------------|
| Simple `updated_at` | 15 | SQLite AFTER UPDATE triggers |
| Cascade deactivation | 2 | `triggers_emulation.go` Go functions |
| Key rotation | 1 | `EmulateKeyRotation()` in Go |
| Key mapping | 3 | Application-layer logic |
| Value ordering | 2 | Application-layer logic |
| Selector extraction | 1 | `ExtractSelectorValues()` in Go |
| Other | 6 | Case-by-case SQLite triggers or Go |

### Key Design Decisions

1. **Key rotation trigger** (324 lines of PL/pgSQL) → Implemented as `EmulateKeyRotation()` in Go
2. **JSONB operations** → Translated to SQLite json1 functions (`json_object`, `json_group_array`)
3. **Array type columns** → Converted to JSON arrays with `json_each()` for iteration
4. **EXCLUDE constraint** → Application-layer validation in `constraints_sqlite.go`
5. **UNIQUE NULLS NOT DISTINCT** → Partial indexes covering NULL combinations
6. **pgtype.\* dependencies** → Query router handles type conversion between drivers
