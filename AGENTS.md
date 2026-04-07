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

The Go toolchain version (`toolchain goX.Y.Z`) is pinned in `go.work` and in every module’s `go.mod`. Two CI workflow files also hardcode it: `.github/workflows/checks.yaml` (`go-version-input`) and `.github/workflows/sonarcloud.yml` (`go-version`).

**Do not update the Go toolchain version by hand in feature PRs.** Instead:

- Toolchain bumps are automated by the `go-version-update` workflow (`.github/workflows/go-version-update.yaml`), which fires automatically when `govulncheck` fails on `main` or a `release/**` branch. It uses the `opentdf-automation[bot]` account and the `chore/bump-go-toolchain` branch.
- To trigger a bump manually: `gh workflow run go-version-update.yaml --field base_branch=main`
- To preview what a bump would change without modifying files: `.github/scripts/bump-go-version.sh --dry-run`

**Minor-version upgrades** (e.g. 1.25 → 1.26) are handled by the same workflow when the current minor falls out of Go’s two-release support window. The `go` directive in every `go.mod` is updated to `X.Y.0` (minimum), and the `toolchain` directive is set to the latest patch.

If `govulncheck` is failing locally because you are on an older toolchain, update your local Go installation rather than editing these files directly.

## Security & Configuration Tips

- Don’t commit secrets/keys. Use local configs like `opentdf-dev.yaml` and follow `SECURITY.md`.
