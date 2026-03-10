# Embedded Postgres Plan (No SQL/Migration Changes)

Goal: Provide a "no external Postgres" mode that still uses the existing Postgres SQL and migrations by starting a local Postgres instance as a child process. This keeps all SQL, migrations, and `pgx` usage unchanged.

## Summary
- Start a real Postgres server from the platform process when `db.embedded.enabled` is true and no external `db.host` is configured.
- Persist mutable state via a mounted root directory.
- Use a fixed image-owned binaries path: `/opt/opentdf/embedded-postgres/binaries`.
- Continue to use the existing `pgx` driver, SQLC queries, and Goose migrations.
- Add only configuration, lifecycle, and docs changes.

## Constraints
- No SQL or migration changes.
- No additional containers.
- Single process using the embedded DB (no distributed writes).

## Design Choice
Use a Go embedded-Postgres launcher to manage:
- `initdb` on first run
- `postgres` process lifecycle
- data directory configuration
- port selection
- clean shutdown

This can be implemented using:
- A library approach (e.g., a Go embedded Postgres launcher), or
- A bundled binary approach (vendor Postgres binaries per OS and spawn them).

The library approach is faster to implement and maintain. The bundled approach avoids downloads at runtime but increases release size and CI complexity.

## Configuration Changes
Add a new `embedded` block under `db` config.

Proposed config shape:
```yaml
# config.yaml

db:
  host: ""                # empty means "use embedded" if enabled
  port: 0                 # 0 means choose a free port when embedded
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
    port: 0              # 0 means select a free port
    start_timeout_seconds: 30
    stop_timeout_seconds: 10
    sslmode: "disable"
```

Resolved internal paths:
- data: `<root_dir>/data`
- runtime: `<root_dir>/runtime`
- cache: `<root_dir>/cache`
- binaries (fixed, image-owned): `/opt/opentdf/embedded-postgres/binaries`

Files to update:
- `service/pkg/config/config.go` (structs + defaults)
- `docs/Configuring.md` (document config)

## Implementation Steps
1. Add config structs
   - Add `db.Embedded` struct to `service/pkg/db/db.go` or `service/pkg/config/config.go`.
   - Provide defaults for `enabled`, `dataDir`, `port`, and timeouts.

2. Add an embedded Postgres launcher
   - Create a small package, e.g. `service/pkg/db/embedded`, with:
     - `Start(ctx, cfg) (host string, port int, stop func(ctx) error, err error)`
     - Idempotent init of the data dir
     - Logging hook to `slog`
   - Ensure it sets `PGDATA` to the configured directory.

3. Wire into DB initialization
   - In `service/pkg/db/db.go`, before building the pgx config:
     - If `db.Embedded.enabled` is true and `db.Host` is empty, start embedded Postgres.
     - Update `db.Host`, `db.Port`, and force `sslmode=disable` for embedded.
   - Store the stop function on `Client` and call it in `Client.Close()`.

4. Keep migrations unchanged
   - No changes required to `service/policy/db/migrations/*.sql`.
   - No changes required to SQLC or `pgx` usage.

5. Add a graceful shutdown path
   - Ensure app shutdown calls `Client.Close()` which stops embedded Postgres.
   - Use timeouts to avoid hanging on shutdown.

6. Update docs
   - Add an "Embedded Postgres" section with:
     - Data directory requirements
     - Disk space and permissions
     - Port selection behavior
     - When to use embedded vs external Postgres
   - Document how to run integration tests with embedded Postgres via env switch

7. Add minimal tests
   - Unit test for config mapping and defaults.
   - Optional integration test that starts embedded Postgres and runs a simple query.
   - Add a test harness switch to run existing integration tests using embedded Postgres instead of containers.

## Operational Notes
- Data directory must be a writable directory (volume mount), not a single file.
- For upgrades, consider version pinning and migration guidance (same as standard Postgres).
- Embedded mode should be explicitly opt-in.

## Rollout
1. Land the embedded launch code and config behind a feature flag.
2. Document usage and provide a sample config.
3. Add a small smoke test to CI if feasible.
