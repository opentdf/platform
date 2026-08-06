# Repository Guidelines

## Project Structure & Module Organization

This repo is a Go workspace (`go.work`) containing multiple Go modules, built using make.

- `service/`: main OpenTDF server and platform services (binary entrypoint: `service/main.go`).
- `sdk/`: Go SDK and generated clients.
- `otdfctl/`: Command line for interacting with server, providing CLI for all SDK operations.
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
- Always run `make fmt` on Go files after making changes.
- Always use signed commits with 'conventional commit' messages.

## Testing Guidelines

### Required Tests Before Committing

**CRITICAL**: All Go code changes must pass these checks before being marked as complete:

1. **Linting**: `make lint`
   - Must pass with 0 new issues
   - Fixes common issues: formatting, shadowing, unused code, suspicious constructs
   - Never let the user discover linting issues from CI

2. **Unit Tests**: `make test` from repo root
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
- **Cross-SDK e2e (xtest)**: the `opentdf/tests` repo runs the platform against the go/java/js SDKs. Use it to validate cross-language behavior (e.g. DPoP, TDF interop) that unit tests can't cover.

### Running xtest on a branch

xtest lives in `opentdf/tests` and is triggered with `gh workflow run`. Push your branch first, then point each `*-ref` input at the branch to test (use the default branch for components you didn't change). Example — testing a platform + otdfctl branch against the standard java/web SDK branches:

```bash
gh workflow run xtest.yml \
  --repo opentdf/tests \
  --ref main \
  -f platform-ref=my-platform-branch \
  -f otdfctl-ref=my-platform-branch \
  -f java-ref=main \
  -f js-ref=main
```

The command prints the run URL. Poll it with `gh run view <run-id> --repo opentdf/tests`, and read a job's logs with `gh run view --job=<job-id> --repo opentdf/tests --log`. When checking a specific feature, confirm its tests actually ran and were not `SKIPPED` (grep the log for the test file, e.g. `test_dpop.py`).

## Commit & Pull Request Guidelines

- Commit messages follow Conventional Commits (e.g., `feat(sdk): ...`, `fix(core): ...`).
- DCO sign-off is required: use `git commit -S -s -m "feat(scope): summary"` (`-S` = cryptographic signing, `-s` = DCO). See `CONTRIBUTING.md`.
- PRs should describe changes, include testing notes, and update docs/tests when applicable (see `.github/pull_request_template.md`).

## Security & Configuration Tips

- Don’t commit secrets/keys. Use local configs like `opentdf-dev.yaml` and follow `SECURITY.md`.
