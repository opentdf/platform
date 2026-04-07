#!/usr/bin/env bats
# Unit tests for bump-go-version.sh
#
# Requirements: bats-core, jq, go (for go mod edit / go work edit)

SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/bump-go-version.sh"
FIXTURES="$(cd "$(dirname "$BATS_TEST_FILENAME")/fixtures" && pwd)"

# Local file URL for the mock go.dev API response.
API_URL="file://${FIXTURES}/go-versions.json"

# ── Helpers ────────────────────────────────────────────────────────────────────

# build_repo ROOT TOOLCHAIN_VER [GO_DIRECTIVE]
#
# Populates ROOT with the minimal file set that bump-go-version.sh touches:
#   go.work, one go.mod per MODULE_DIRS entry, and stub workflow YAML files.
#
# TOOLCHAIN_VER  e.g. "1.25.7"
# GO_DIRECTIVE   e.g. "1.25.0"  (defaults to TOOLCHAIN_VER if omitted)
build_repo() {
  local root="$1"
  local toolchain="$2"
  local go_dir="${3:-${toolchain}}"

  # go.work
  mkdir -p "$root"
  cat > "${root}/go.work" <<EOF
go ${go_dir}

toolchain go${toolchain}

use (
	./examples
	./lib/fixtures
	./lib/flattening
	./lib/identifier
	./lib/ocrypto
	./protocol/go
	./sdk
	./service
	./tests-bdd
)
EOF

  # One go.mod per module directory
  for mod_dir in \
      examples sdk service \
      lib/fixtures lib/flattening lib/identifier lib/ocrypto \
      protocol/go tests-bdd test/integration; do
    mkdir -p "${root}/${mod_dir}"
    local mod_name
    mod_name="github.com/opentdf/platform/${mod_dir}"
    cat > "${root}/${mod_dir}/go.mod" <<EOF
module ${mod_name}

go ${go_dir}

toolchain go${toolchain}
EOF
  done

  # Stub CI workflow files
  mkdir -p "${root}/.github/workflows"
  cat > "${root}/.github/workflows/checks.yaml" <<EOF
name: Checks
jobs:
  go:
    steps:
      - name: govulncheck
        uses: golang/govulncheck-action@abc123
        with:
          go-version-input: "1.25.7"
EOF

  cat > "${root}/.github/workflows/sonarcloud.yml" <<EOF
name: SonarCloud
jobs:
  gotest:
    steps:
      - name: Setup Go
        uses: actions/setup-go@abc123
        with:
          go-version: "1.25.7"
EOF
}

# ── Tests ──────────────────────────────────────────────────────────────────────

@test "patch version bump updates toolchain in go.work and all go.mod files" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.7" "1.25.0"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9"
  [ "$status" -eq 0 ]

  # go.work toolchain
  grep -q "toolchain go1.25.9" "${root}/go.work"

  # Spot-check a few modules
  grep -q "toolchain go1.25.9" "${root}/service/go.mod"
  grep -q "toolchain go1.25.9" "${root}/sdk/go.mod"
  grep -q "toolchain go1.25.9" "${root}/test/integration/go.mod"
}

@test "patch version bump does not change the go directive" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.7" "1.25.0"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9"
  [ "$status" -eq 0 ]

  # go directive must stay at 1.25.0
  grep -q "^go 1\.25\.0$" "${root}/go.work"
  grep -q "^go 1\.25\.0$" "${root}/service/go.mod"
}

@test "minor version bump updates go directive to X.Y.0" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.24.3" "1.24.0"

  run "$SCRIPT" --repo-root "$root" --target "1.26.1"
  [ "$status" -eq 0 ]

  # go directive must become 1.26.0
  grep -q "^go 1\.26\.0$" "${root}/go.work"
  grep -q "^go 1\.26\.0$" "${root}/sdk/go.mod"
  grep -q "^go 1\.26\.0$" "${root}/test/integration/go.mod"

  # toolchain must become 1.26.1
  grep -q "toolchain go1\.26\.1" "${root}/go.work"
  grep -q "toolchain go1\.26\.1" "${root}/service/go.mod"
}

@test "already at target version exits with code 2 and does not modify files" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.9" "1.25.0"

  # Capture mtime of go.work to verify no write happened
  local before_mtime
  before_mtime="$(stat -c %Y "${root}/go.work" 2>/dev/null || stat -f %m "${root}/go.work")"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9"
  [ "$status" -eq 2 ]

  local after_mtime
  after_mtime="$(stat -c %Y "${root}/go.work" 2>/dev/null || stat -f %m "${root}/go.work")"
  [ "$before_mtime" -eq "$after_mtime" ]
}

@test "dry-run outputs a unified diff and does not modify files" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.7" "1.25.0"

  # Capture original content
  local orig_toolchain
  orig_toolchain="$(grep "^toolchain " "${root}/go.work")"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9" --dry-run
  [ "$status" -eq 0 ]

  # Output must contain a diff header
  [[ "$output" == *"--- a/go.work"* ]]
  [[ "$output" == *"+toolchain go1.25.9"* ]]

  # Original file must be untouched
  grep -q "$orig_toolchain" "${root}/go.work"
}

@test "dry-run with already-at-latest exits 2 and produces no diff output" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.9" "1.25.0"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9" --dry-run
  [ "$status" -eq 2 ]
  [ -z "$output" ] || [[ "$output" != *"---"* ]]
}

@test "CI YAML files are updated unconditionally even if they lag the toolchain" {
  local root="${BATS_TEST_TMPDIR}/repo"
  # Repo toolchain is 1.25.8 but YAML files still reference 1.25.7
  build_repo "$root" "1.25.8" "1.25.0"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9"
  [ "$status" -eq 0 ]

  grep -q 'go-version-input: "1.25.9"' "${root}/.github/workflows/checks.yaml"
  grep -q 'go-version: "1.25.9"' "${root}/.github/workflows/sonarcloud.yml"
}

@test "EOL minor version detection upgrades to latest supported minor" {
  local root="${BATS_TEST_TMPDIR}/repo"
  # 1.23.x is EOL (not in the two most recent minors per fixtures: 1.25, 1.24)
  build_repo "$root" "1.23.8" "1.23.0"

  run "$SCRIPT" --repo-root "$root" --api-url "$API_URL"
  [ "$status" -eq 0 ]

  # Should have been bumped to the latest minor (1.25.9 per fixtures)
  grep -q "toolchain go1\.25\." "${root}/go.work"
  grep -q "^go 1\.25\.0$" "${root}/go.work"
}

@test "API lookup picks latest patch for current in-support minor" {
  local root="${BATS_TEST_TMPDIR}/repo"
  # 1.25.7 is not the latest patch in fixtures (1.25.9 is)
  build_repo "$root" "1.25.7" "1.25.0"

  run "$SCRIPT" --repo-root "$root" --api-url "$API_URL"
  [ "$status" -eq 0 ]

  grep -q "toolchain go1\.25\.9" "${root}/go.work"
  # go directive must NOT change (still a patch bump)
  grep -q "^go 1\.25\.0$" "${root}/go.work"
}

@test "prerelease versions (stable: false) are excluded from version selection" {
  local root="${BATS_TEST_TMPDIR}/repo"
  # Fixtures include go1.26rc1 (stable: false); current minor 1.25 is still supported.
  # The script must NOT upgrade to 1.26 and must pick 1.25.9 as the latest stable patch.
  build_repo "$root" "1.25.7" "1.25.0"

  run "$SCRIPT" --repo-root "$root" --api-url "$API_URL"
  [ "$status" -eq 0 ]

  grep -q "toolchain go1\.25\.9" "${root}/go.work"
  ! grep -q "toolchain go1\.26" "${root}/go.work"
}
