#!/usr/bin/env bats

# Tests for `otdfctl validate` (DSPX-5350), which runs sdk.IsValidTdf.
#
# Validation is offline, so no case here passes a host or credentials, and the
# file needs no platform or policy fixtures. The exit codes are a contract with
# the xtest validity suite: 0 valid, 3 not a valid TDF, anything else means the
# check could not run.

setup_file() {
  # Written by the Go SDK; the unit tests in cmd/tdf use the same file.
  export VALID_TDF="$PWD/cmd/tdf/testdata/valid.tdf"
}

setup() {
  bats_load_library bats-support
  bats_load_library bats-assert
}

@test "validate: a valid TDF exits 0" {
  run --separate-stderr -- ./otdfctl validate "$VALID_TDF"
  assert_success
  assert_output '{"valid":true}'
}

@test "validate: a file that is not a TDF exits 3 with a reason" {
  local garbage="$BATS_TEST_TMPDIR/garbage.tdf"
  printf 'this is not a TDF\n' >"$garbage"

  run --separate-stderr -- ./otdfctl validate "$garbage"
  assert_failure 3
  assert_equal "$(jq -r '.valid' <<<"$output")" "false"
  assert_not_equal "$(jq -r '.reason // ""' <<<"$output")" ""
}

@test "validate: a missing file exits neither 0 nor 3" {
  run --separate-stderr -- ./otdfctl validate "$BATS_TEST_TMPDIR/missing.tdf"
  assert_failure
  assert_not_equal "$status" 3
  assert_output ''
}
