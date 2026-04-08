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
#   go.work, one go.mod per MODULE_DIRS entry.
#   go.mod files intentionally have NO toolchain directive (matches production).
#
# TOOLCHAIN_VER  e.g. "1.25.7"  — written to go.work only
# GO_DIRECTIVE   e.g. "1.25.0"  (defaults to minor.0 of TOOLCHAIN_VER)
build_repo() {
  local root="$1"
  local toolchain="$2"
  local minor
  minor="$(echo "$toolchain" | cut -d. -f1,2)"
  local go_dir="${3:-${minor}.0}"

  # go.work — the only place that carries a toolchain directive
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

  # One go.mod per module directory — NO toolchain directive
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
EOF
  done
}

# ── Tests ──────────────────────────────────────────────────────────────────────

@test "patch bump updates only go.work toolchain — go.mod files untouched" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.7"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9"
  [ "$status" -eq 0 ]

  # go.work toolchain updated
  grep -q "toolchain go1.25.9" "${root}/go.work"
  # go.work go directive unchanged
  grep -q "^go 1\.25\.0$" "${root}/go.work"

  # go.mod files must NOT have a toolchain line
  ! grep -q "^toolchain" "${root}/service/go.mod"
  ! grep -q "^toolchain" "${root}/sdk/go.mod"
  # go.mod go directive unchanged
  grep -q "^go 1\.25\.0$" "${root}/service/go.mod"
}

@test "minor version bump updates go directive in go.work and all go.mod files" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.24.3"

  run "$SCRIPT" --repo-root "$root" --target "1.26.1"
  [ "$status" -eq 0 ]

  # go.work: toolchain and go directive both updated
  grep -q "toolchain go1\.26\.1" "${root}/go.work"
  grep -q "^go 1\.26\.0$" "${root}/go.work"

  # go.mod: go directive updated, still no toolchain
  grep -q "^go 1\.26\.0$" "${root}/sdk/go.mod"
  grep -q "^go 1\.26\.0$" "${root}/test/integration/go.mod"
  ! grep -q "^toolchain" "${root}/sdk/go.mod"
}

@test "already at target version exits with code 2 and does not modify files" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.9"

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
  build_repo "$root" "1.25.7"

  local orig_toolchain
  orig_toolchain="$(grep "^toolchain " "${root}/go.work")"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9" --dry-run
  [ "$status" -eq 0 ]

  # Output must contain a diff for go.work
  [[ "$output" == *"--- a/go.work"* ]]
  [[ "$output" == *"+toolchain go1.25.9"* ]]
  # Output must NOT contain go.mod diffs (patch bump = go.work only)
  [[ "$output" != *"go.mod"* ]]

  # Original file must be untouched
  grep -q "$orig_toolchain" "${root}/go.work"
}

@test "dry-run with already-at-latest exits 2" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.9"

  run "$SCRIPT" --repo-root "$root" --target "1.25.9" --dry-run
  [ "$status" -eq 2 ]
}

@test "dry-run for minor bump includes go.mod diffs" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.24.3"

  run "$SCRIPT" --repo-root "$root" --target "1.26.1" --dry-run
  [ "$status" -eq 0 ]

  # Must show diffs for go.work AND go.mod files
  [[ "$output" == *"--- a/go.work"* ]]
  [[ "$output" == *"--- a/sdk/go.mod"* ]]
  [[ "$output" == *"+go 1.26.0"* ]]
}

@test "EOL minor version detection upgrades to latest supported minor" {
  local root="${BATS_TEST_TMPDIR}/repo"
  # 1.23.x is EOL (not in the two most recent minors per fixtures: 1.25, 1.24)
  build_repo "$root" "1.23.8"

  run "$SCRIPT" --repo-root "$root" --api-url "$API_URL"
  [ "$status" -eq 0 ]

  # Should have been bumped to the latest minor (1.25.9 per fixtures)
  grep -q "toolchain go1\.25\." "${root}/go.work"
  grep -q "^go 1\.25\.0$" "${root}/go.work"
  # go.mod go directive also updated (minor bump)
  grep -q "^go 1\.25\.0$" "${root}/service/go.mod"
}

@test "API lookup picks latest patch for current in-support minor" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.7"

  run "$SCRIPT" --repo-root "$root" --api-url "$API_URL"
  [ "$status" -eq 0 ]

  grep -q "toolchain go1\.25\.9" "${root}/go.work"
  # go directive must NOT change (patch bump)
  grep -q "^go 1\.25\.0$" "${root}/go.work"
}

@test "prerelease versions (stable: false) are excluded from version selection" {
  local root="${BATS_TEST_TMPDIR}/repo"
  # Fixtures include go1.26rc1 (stable: false); current minor 1.25 is still supported.
  build_repo "$root" "1.25.7"

  run "$SCRIPT" --repo-root "$root" --api-url "$API_URL"
  [ "$status" -eq 0 ]

  grep -q "toolchain go1\.25\.9" "${root}/go.work"
  ! grep -q "toolchain go1\.26" "${root}/go.work"
}

@test "missing --target value produces a helpful error" {
  local root="${BATS_TEST_TMPDIR}/repo"
  build_repo "$root" "1.25.7"

  run "$SCRIPT" --repo-root "$root" --target
  [ "$status" -eq 1 ]
  [[ "$output" == *"requires a non-empty value"* ]]
}
