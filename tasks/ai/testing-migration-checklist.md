# Testing Migration Checklist

## Status
Completed

## Workstreams (parallelizable)

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
