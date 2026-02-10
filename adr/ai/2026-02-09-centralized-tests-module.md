# Centralize Containerized and BDD Tests Under tests/

## Status
Accepted

## Context
We want to remove the `testcontainers` dependency from the `sdk` and `service` modules while keeping integration and BDD coverage. The existing layout splits BDD tests under `tests-bdd/` and containerized integration tests inside `sdk/` and `service/`, which ties those modules to `testcontainers` and increases dependency weight.

## Decision
- Create a single root `tests/` Go module that contains all BDD and containerized integration tests.
- Move SDK OAuth, Service integration, and ERS integration tests into `tests/`.
- Keep `lib/fixtures` versioned (for now) and move service fixture helpers into it for tests and quickstart workflows.
- Use `go.work` for local module resolution across `sdk`, `service`, `protocol/go`, and `lib/fixtures`.

## Consequences
- `sdk` and `service` drop `testcontainers` from their `go.mod` files.
- Integration and BDD tests are run via `cd tests && go test ./...`.
- `lib/fixtures` now depends on `service` and `protocol/go`, which increases coupling and should be monitored for release friction.
- CI and documentation must point to the new `tests/` location.

## Migration Checklist (Completed)

### 1) BDD migration (tests-bdd -> tests)
- [x] Move `tests-bdd/` to `tests/`
- [x] Update module path, imports, and docs
- [x] Update Dockerfile and root references

### 2) SDK OAuth integration tests
- [x] Move OAuth tests under `tests/sdk/auth/oauth`
- [x] Move testdata and update package imports
- [x] Ensure Keycloak container setup works

### 3) Service integration tests
- [x] Move `service/integration` tests under `tests/service/integration`
- [x] Replace fixture loading with `lib/fixtures`
- [x] Use shared container helpers

### 4) ERS integration tests
- [x] Move ERS integration tests under `tests/service/entityresolution/integration`
- [x] Update internal package imports
- [x] Update docs and docker-compose data mounts

### 5) Fixtures consolidation
- [x] Move `service/internal/fixtures` into `lib/fixtures`
- [x] Embed `policy_fixtures.yaml` and update loaders
- [x] Update `service/cmd/provisionFixtures.go`

### 6) Cleanup and wiring
- [x] Remove `testcontainers` from `sdk` and `service` go.mod
- [x] Update `go.work` to include `tests/`
- [x] Add `make test-integration` and document usage
- [x] Run `go mod tidy` and formatting
