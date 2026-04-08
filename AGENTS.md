# Repository Guidelines

## Project Structure & Module Organization

This repo is a Go workspace (`go.work`) containing multiple Go modules:

- `service/`: main OpenTDF server and platform services (binary entrypoint: `service/main.go`).
- `sdk/`: Go SDK and generated clients.
- `lib/*/`: shared libraries (e.g., `lib/ocrypto`, `lib/identifier`).
- `protocol/` and `service/`: protobuf sources; generated Go lives under `protocol/go/` and docs under `docs/grpc/` + `docs/openapi/`.
- `tests-bdd/`: BDD/integration-style tests (Godog) and feature files (`tests-bdd/features/`).
- `docs/`, `examples/`, `adr/`: documentation, example code, and architecture decisions.

## Build, Test, and Development Commands

Prefer `make` targets at repo root:

- `make toolcheck`: verifies required tooling (Buf, golangci-lint, generators).
- `make build`: regenerates protos/codegen and builds `opentdf` + `sdk` + `examples`.
- `make lint`: runs `buf lint`, `golangci-lint`, and `govulncheck` across modules.
- `make test`: runs `go test ./... -race` across core modules (does **not** include `tests-bdd/`).
- `docker compose up`: brings up local infra (Postgres + Keycloak). See `docs/Contributing.md`.

## Coding Style & Naming Conventions

- Go formatting is enforced: run `make fmt` (uses `golangci-lint fmt`; Go uses tabs for indentation).
- Imports should be goimports-compatible; keep package names lowercase; exported identifiers use `PascalCase`.
- Protobuf changes must pass `buf lint` and should be regenerated via `make proto-generate`.
- Always run `gofumpt` on Go files after making changes
- The project uses `gofumpt` (stricter than `gofmt`) for formatting
- Before completing Go-related tasks, run: `~/go/bin/gofumpt -w <files>`

## Testing Guidelines

### Required Tests Before Committing

**CRITICAL**: All Go code changes must pass these checks before being marked as complete:

1. **Linting**: `golangci-lint run ./path/to/changed/files.go`
   - Must pass with 0 issues
   - Fixes common issues: formatting, shadowing, unused code, suspicious constructs
   - Never let the user discover linting issues from CI

2. **Unit Tests**: `go test ./...` (or `make test` from repo root)
   - All existing tests must continue to pass
   - Add tests for new functionality

3. **README Code Block Tests**:
   - SDK README examples: `cd sdk && go test -run TestREADMECodeBlocks`
   - Ensures documentation examples remain compilable

### Test Types

- **Unit tests**: `*_test.go` next to code; run `make test`.
- **BDD tests**: run `cd tests-bdd && go test ./...` (requires Docker; feature files are `tests-bdd/features/*.feature`).
- **Integration tests** may require the compose stack; follow module README(s) under `service/`.
- **README tests**: verify code examples in documentation compile and work correctly.

## Commit & Pull Request Guidelines

- Commit messages follow Conventional Commits (e.g., `feat(sdk): ...`, `fix(core): ...`).
- DCO sign-off is required: use `git commit -s -m "feat(scope): summary"`. See `CONTRIBUTING.md`.
- PRs should describe changes, include testing notes, and update docs/tests when applicable (see `.github/pull_request_template.md`).

## Go Toolchain Version Management

**`go.work` is the single source of truth for the Go toolchain version.** Its `toolchain goX.Y.Z` directive controls which Go version is used for workspace builds and CI. Individual `go.mod` files intentionally have **no `toolchain` directive** — the workspace handles it, and omitting it avoids imposing a specific toolchain on downstream consumers of our published modules (sdk, protocol/go, lib/*).

CI workflows read the Go version from `go.work` via `go-version-file: go.work`, so there are no hardcoded version strings in YAML files.

**Do not update the Go toolchain version by hand in feature PRs.** Instead:

- Toolchain bumps are automated by the `go-version-update` workflow (`.github/workflows/go-version-update.yaml`), which fires automatically when `govulncheck` fails on `main` or a `release/**` branch. It uses the `opentdf-automation[bot]` account and the `chore/bump-go-toolchain` branch.
- To trigger a bump manually: `gh workflow run go-version-update.yaml --field base_branch=main`
- To preview what a bump would change without modifying files: `.github/scripts/bump-go-version.sh --dry-run`
- **Patch bumps** (e.g. 1.25.8 → 1.25.9) only modify `go.work` — one file.
- **Minor-version upgrades** (e.g. 1.25 → 1.26) also update the `go` directive in `go.work` and all `go.mod` files. This is triggered when the current minor falls out of Go’s two-release support window.

**Do not add `toolchain` directives to go.mod files.** If `go mod tidy` or another tool adds one, remove it with `go mod edit -toolchain=none path/to/go.mod`.

If `govulncheck` is failing locally because you are on an older toolchain, update your local Go installation rather than editing version files directly.

## Security & Configuration Tips

- Don’t commit secrets/keys. Use local configs like `opentdf-dev.yaml` and follow `SECURITY.md`.
