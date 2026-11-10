# Claude Code Instructions

## Overview

This file provides instructions for AI agents working on the OpenTDF Platform codebase.

**For complete repository guidelines, coding standards, and development workflow, see [AGENTS.md](AGENTS.md).**

## Critical Requirements

### Before Completing ANY Go Code Changes

**MANDATORY CHECKS** - Run these before marking work as complete:

1. **Linting**: `golangci-lint run ./path/to/changed/files.go`
   - Must pass with 0 issues
   - User should NEVER discover linting issues from CI

2. **Unit Tests**: `go test ./...` or `make test`
   - All existing tests must pass
   - Add tests for new functionality

3. **README Tests** (if SDK changes): `cd sdk && go test -run TestREADMECodeBlocks`
   - Ensures documentation examples remain compilable

### Formatting

- Run `gofumpt -w <files>` on all changed Go files before completing
- Use tabs for indentation (Go standard)

### Key Guidelines from AGENTS.md

- **Project Structure**: Go workspace with multiple modules (service, sdk, lib/*)
- **Build Commands**: Use `make` targets (build, test, lint, fmt)
- **Commit Style**: Conventional Commits with DCO sign-off (`git commit -s`)
- **Testing**: Unit tests, BDD tests, integration tests - see AGENTS.md for details

## Remember

✅ Run linting checks proactively - don't let CI catch issues
✅ Test changes locally before marking complete
✅ Follow patterns and conventions in AGENTS.md
✅ Update documentation when changing APIs