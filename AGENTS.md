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

## Security & Configuration Tips

- Don’t commit secrets/keys. Use local configs like `opentdf-dev.yaml` and follow `SECURITY.md`.

## Spec-Driven Architecture Workflow

For cross-cutting changes in this repo, prefer the repo’s spec-driven workflow over coding directly from vague intent.

Use ADR/spec/proto artifacts when work:

- spans multiple layers (`service`, `proto`, `sdk`, `cli`, `docs/ops`)
- introduces or changes a public/service seam
- affects compatibility, rollout, or fallback behavior
- changes service ownership or modular-binary placement

Artifact hierarchy:

- **ADR** — broad architectural direction, tradeoffs, rejected alternatives, future phases
- **Spec** — current-phase behavioral contract
- **Proto** — tight seam/service contract, narrower than the spec

Monorepo layers:

- `service` — runtime/server behavior, modular-binary placement, config, auth
- `proto` — wire/service contract
- `sdk` — client behavior, capability detection, fallback
- `cli` — operator/developer UX
- `docs/ops` — rollout, migration, deployment guidance

Rules:

- Do not blur service ownership just because multiple services can run in one binary. Even in `all` mode, namespace/runtime ownership still matters.
- Proto changes should be additive by default. Do not add speculative future-phase fields without a current-phase spec need.
- If unresolved questions materially affect service ownership, proto shape, SDK behavior, fallback behavior, rollout, or validation, stop and escalate rather than guessing.

Detailed guidance:

- `docs/specs/AGENTS.md`
- `docs/agents/AGENTS.md`
- `docs/agents/adr-spec-proto-orchestration.md`
- `docs/agents/effort-routing-and-agent-quality.md`
- `docs/agents/spec-executor.md`

Shared agent playbooks live under `docs/agents/`. Harness-specific wrappers may live under `.pi/agents/` and should reference the shared docs rather than redefining the workflow.
