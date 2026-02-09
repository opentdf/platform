# Centralize Containerized and BDD Tests Under tests/

## Status
Accepted

## Context
We want to remove the `testcontainers` dependency from the `sdk` and `service` modules while keeping integration and BDD coverage. The existing layout splits BDD tests under `tests-bdd/` and containerized integration tests inside `sdk/` and `service/`, which ties those modules to `testcontainers` and increases dependency weight.

## Decision
- Create a single root `tests/` Go module that contains all BDD and containerized integration tests.
- Move SDK OAuth, Service integration, and ERS integration tests into `tests/`.
- Make `lib/fixtures` repo-internal (unversioned) and move service fixture helpers into it.
- Use `go.work` for local module resolution across `sdk`, `service`, `protocol/go`, and `lib/fixtures`.

## Consequences
- `sdk` and `service` drop `testcontainers` from their `go.mod` files.
- Integration and BDD tests are run via `cd tests && go test ./...`.
- `lib/fixtures` now depends on `service` and `protocol/go`, which is acceptable for repo-internal use but increases coupling.
- CI and documentation must point to the new `tests/` location.
