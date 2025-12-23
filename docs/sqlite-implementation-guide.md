# SQLite Implementation Guide

This document outlines the steps required to support SQLite as a drop-in replacement for the current PostgreSQL implementation in the OpenTDF platform.

## Overview

The current implementation is tightly coupled with PostgreSQL through:
- **pgx driver** (`github.com/jackc/pgx/v5`) for connections
- **sqlc** code generation configured for PostgreSQL (11 query files → 11 generated `.sql.go` files)
- **Squirrel** query builder with `$` placeholder format
- **38 migration files** using PostgreSQL-specific SQL features
- **30 database triggers** (including complex PL/pgSQL functions)
- **PostgreSQL-specific error handling** via `pgerrcode`
- **pgtype.\*** wrappers for PostgreSQL types in Go models

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
- [ ] Evaluate if SQLite feature limitations are acceptable for use case
- [ ] Decide on migration strategy (parallel migrations vs. conditional)
- [ ] Plan for trigger logic migration (application layer)

### Core Changes
- [ ] Create driver abstraction interface (`service/pkg/db/driver.go`)
- [ ] Implement SQLite connection wrapper
- [ ] Update configuration to support driver selection
- [ ] Modify Squirrel placeholder format based on driver
- [ ] Create SQLite-specific error mapping

### Migration Files (38 files)
- [ ] Create `migrations_sqlite/` directory
- [ ] Convert 38 migration files to SQLite syntax
- [ ] Replace 28 `gen_random_uuid()` calls with application-layer UUID generation
- [ ] Convert 66 JSONB column definitions to TEXT/JSON
- [ ] Replace 6 array columns with JSON or junction tables
- [ ] Rewrite 30 triggers (15 simple, 15 complex requiring app logic)
- [ ] Convert ENUM type to CHECK constraint
- [ ] Handle `UNIQUE NULLS NOT DISTINCT` with partial indexes (20240213)
- [ ] Handle `EXCLUDE` constraint with application logic (20241125)

### Query Layer (11 query files, 11 generated .sql.go files)
- [ ] Audit all 11 sqlc query files in `queries/` for PostgreSQL syntax
- [ ] Create SQLite-compatible query files in `queries_sqlite/`
- [ ] Rewrite 479 JSON aggregation function calls
- [ ] Replace `JSON_BUILD_OBJECT` with `json_object`
- [ ] Replace `JSONB_AGG` with `json_group_array`
- [ ] Handle `ANY(array)` → `IN (...)` conversion
- [ ] Replace COPY protocol with batch inserts in `copyfrom.go`
- [ ] Update `pgtype.*` usage in `models.go` to driver-agnostic types

### Testing
- [ ] Create SQLite integration test suite
- [ ] Add SQLite to CI test matrix
- [ ] Validate data type conversions
- [ ] Performance benchmarks

### Documentation
- [ ] Update deployment documentation
- [ ] Document SQLite-specific configuration
- [ ] Document feature limitations

---

## Estimated Complexity

| Component | Files Affected | Details | Complexity |
|-----------|----------------|---------|------------|
| Connection abstraction | 3-5 new files | New driver interface + factory | Medium |
| Error handling | 1 file (`errors.go`) | Add SQLite error mapping | Low |
| Query builder config | 1 file (`db.go`) | Placeholder format switch | Low |
| Migration conversion | 38 SQL files | Full SQLite rewrites | High |
| Trigger logic migration | 6-8 Go files | 30 triggers → app logic | High |
| sqlc query rewrites | 22 files | 11 queries + 11 generated | High |
| Type mapping layer | 2-3 files | `pgtype.*` → stdlib types | Medium |
| Bulk insert replacement | 1 file (`copyfrom.go`) | COPY → batch INSERT | Medium |
| Testing infrastructure | 5-10 files | Parallel test suites | Medium |

### Effort Breakdown by Trigger Complexity

| Trigger Type | Count | Estimated Effort |
|--------------|-------|------------------|
| Simple `updated_at` | 15 | 1-2 hours (direct SQLite port) |
| Cascade deactivation | 2 | 4-8 hours (split into multiple triggers) |
| Key rotation | 1 | 16-24 hours (324-line function → Go) |
| Key mapping | 3 | 8-12 hours (application logic) |
| Value ordering | 2 | 4-6 hours (application logic) |
| Selector extraction | 1 | 4-8 hours (JSONB parsing in Go) |
| Other | 6 | 8-12 hours (case-by-case) |

**Key Risk Areas:**
1. **Key rotation trigger** (324 lines of PL/pgSQL) - Most complex single piece; handles active key transitions with mapping copies
2. **JSONB operations** - 479 occurrences across 24 files; pervasive and requires thorough testing
3. **Array type columns** - 6 columns need structural changes (junction tables or JSON serialization)
4. **EXCLUDE constraint** - Cannot be replicated in SQLite; requires application-layer validation for unique active keys
5. **UNIQUE NULLS NOT DISTINCT** - PostgreSQL 15+ feature; requires partial index or application logic in SQLite
6. **pgtype.\* dependencies** - Models use PostgreSQL-specific type wrappers that need abstraction
