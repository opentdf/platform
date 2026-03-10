# Embedded Postgres Mode Spec

Date: 2026-03-06

## Goal
Provide an opt-in embedded Postgres mode that allows full CRUD functionality with **zero SQL or migration changes**. The platform starts and manages a local Postgres server as a child process and uses the existing `pgx` driver, SQLC queries, and Goose migrations unchanged.

## Non-Goals
- Replacing Postgres with another SQL engine.
- Supporting multi-process writers against the same data directory.
- Modifying or dual-running SQL/migrations for other engines.
- Cross-host/high-availability embedded mode.

## User Stories
1. As an operator, I want to run the platform on a single host without an external Postgres instance, while keeping all CRUD APIs working.
2. As a developer, I want to run the service locally without Docker/containers and still use the existing schema and migrations.
3. As a tester, I want to run integration tests without needing a separate Postgres container.

## Requirements
### Functional
1. When `db.embedded.enabled=true` and `db.host` is empty, the service must start a Postgres server locally and connect using the existing Postgres driver.
2. The embedded instance must persist mutable state under a configured root directory (not a file).
3. Migrations must run as they do today (no schema changes).
4. Shutdown must gracefully stop the embedded server and release file locks.
5. Configuration must allow disabling embedded mode and using an external Postgres unchanged.

### Non-Functional
1. Minimal startup overhead; fail fast with clear errors if init/start fails.
2. Predictable shutdown within a configurable timeout.
3. Clear logging of embedded lifecycle and connection details (without secrets).
4. Default configuration should be safe for local development.

## Config Spec
Add an `embedded` block under `db` configuration:

```yaml
db:
  host: ""                # empty + embedded.enabled=true => start embedded
  port: 0                 # 0 => dynamic port
  database: "opentdf"
  user: "postgres"
  password: "changeme"
  sslmode: "disable"      # embedded should default to disable
  schema: "opentdf"
  runMigrations: true
  verifyConnection: true

  embedded:
    enabled: true
    root_dir: "/var/lib/opentdf/pg"
    port: 0              # 0 => select free port
    start_timeout_seconds: 30
    stop_timeout_seconds: 10
    sslmode: "disable"
```

### Config Behavior
- If `embedded.enabled=false`, never start embedded Postgres.
- If `embedded.enabled=true` and `db.host` is non-empty, do **not** start embedded; use external DB.
- If `embedded.enabled=true` and `db.host` is empty:
  - Start embedded Postgres.
  - Inject `db.host=localhost` and the embedded port into the DB config.
  - Force `sslmode=disable` unless explicitly overridden.
  - `embedded.root_dir` is required and must be writable.
  - Mutable paths are derived as `<root_dir>/data`, `<root_dir>/runtime`, `<root_dir>/cache`.
  - Binaries path is fixed and image-owned: `/opt/opentdf/embedded-postgres/binaries`.

## Lifecycle
### Startup
1. Read config.
2. If embedded is enabled and no external host is provided:
   - Ensure `dataDir` exists and is writable.
   - Initialize cluster (`initdb`) if uninitialized.
   - Start `postgres` with:
     - `-D <dataDir>`
     - `-p <port>`
   - Wait until accepting connections or fail by `startTimeoutSeconds`.
3. Construct `pgx` config and connect using existing logic.
4. Run migrations if enabled.

### Shutdown
1. Close `pgx` pool and SQL DB.
2. Stop embedded Postgres with timeout.
3. Log and surface any stop failures (do not hang indefinitely).

## Error Handling
- Data dir not writable => fail with clear message.
- Init or start fails => fail fast and surface stderr.
- Port in use => retry with dynamic port if configured to 0, otherwise fail.

## Observability
- Log embedded start/stop events with data dir and port (no secrets).
- Track startup duration and exit status.
- Emit a single warning if embedded mode is used in non-dev environments (optional).

## Compatibility
- Requires OS-specific Postgres binaries.
- Embedded mode should be supported for the same OSes as the platform binaries.
- Runtime does not configure a binaries path; binaries are expected at a fixed image path.
- No SQL or migration changes required.

## Security
- Local-only by default (bind to `127.0.0.1`).
- No external network exposure unless explicitly configured.
- Keep passwords and DSNs out of logs.

## Testability Assessment
### What is testable
1. **Config parsing defaults**
   - Unit tests for `db.embedded` defaults and override behavior.
2. **Embedded start/stop lifecycle**
   - Integration test that starts embedded Postgres, runs a simple query, and stops.
3. **Migration compatibility**
   - Smoke test that runs migrations against embedded Postgres and verifies version table.
4. **External DB precedence**
   - Test that `db.host` overrides embedded mode (embedded not started).

### What is hard to test (and how to mitigate)
1. **OS-specific binaries**
   - Mitigation: CI matrix by OS or skip embedded tests on unsupported OS.
2. **Data dir permissions**
   - Mitigation: unit test for error handling using temp dir with restricted perms.
3. **Port contention**
   - Mitigation: test dynamic port selection when `port=0`.
4. **Shutdown timeouts**
   - Mitigation: inject a fake launcher or interface for lifecycle methods.

### Recommended Test Plan
- Unit tests:
  - Config parsing and precedence rules.
  - Data dir validation (read/write).
- Integration tests (optional; can be tagged):
  - Embedded startup + simple query.
  - Migrations run successfully (goose version table exists).
  - Run existing integration tests with an env switch that selects embedded Postgres.

### Risk Assessment
- **Low risk** for correctness: uses real Postgres engine with existing SQL/migrations.
- **Medium operational risk**: requires correct Postgres binary packaging and lifecycle management.
- **Test risk**: integration tests may be flaky without stable binaries or OS support.

## Integration Test Switch
Add a test harness switch so existing integration tests can run with embedded Postgres.

Environment variables:
- `OPENTDF_TEST_DB_PROVIDER`: `container` (default) or `embedded`.
- `OPENTDF_TEST_DB_DATA_DIR`: optional data directory for embedded mode (defaults to temp dir).
- `OPENTDF_TEST_DB_PORT`: optional fixed port for embedded mode (default selects a free port).
- `OPENTDF_TEST_DB_BINARIES_DIR`: optional directory for cached Postgres binaries (avoid re-downloads).
- `OPENTDF_TEST_DB_RUNTIME_DIR`: optional runtime directory for embedded mode.
