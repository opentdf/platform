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

- Unit tests: `*_test.go` next to code; run `make test`.
- BDD tests: run `cd tests-bdd && go test ./...` (requires Docker; feature files are `tests-bdd/features/*.feature`).
- Integration tests may require the compose stack; follow module README(s) under `service/`.

## Commit & Pull Request Guidelines

- Commit messages follow Conventional Commits (e.g., `feat(sdk): ...`, `fix(core): ...`).
- DCO sign-off is required: use `git commit -s -m "feat(scope): summary"`. See `CONTRIBUTING.md`.
- PRs should describe changes, include testing notes, and update docs/tests when applicable (see `.github/pull_request_template.md`).

## Security & Configuration Tips

- Don’t commit secrets/keys. Use local configs like `opentdf-dev.yaml` and follow `SECURITY.md`.
