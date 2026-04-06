#!/usr/bin/env bats

# NEEDS TO RUN AFTER encrypt-decrypt.bats
load "${BATS_LIB_PATH}/bats-support/load.bash"
load "${BATS_LIB_PATH}/bats-assert/load.bash"
load "otdfctl-utils.sh"

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  # Create a KAS registry entry for testing base keys
  export KAS_NAME_BASE_KEY_TEST="kas-registry-for-base-key-tests"
  export KAS_URI_BASE_KEY_TEST="https://test-kas-for-base-keys.com"
  export KAS_REGISTRY_ID_BASE_KEY_TEST=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --name "${KAS_NAME_BASE_KEY_TEST}" --uri "${KAS_URI_BASE_KEY_TEST}" --json | jq -r '.id')

  # Create a regular KAS key to be set as a base key
  # This key will be used by the 'set' command tests
  export REGULAR_KEY_ID_FOR_BASE_TEST="regular-key-for-base-$(date +%s)"
  export WRAPPING_KEY="9453b4d7cc55cf27926ae8f98a9d5aa159d51b7a4d478e440271ab261792a2bd"
  export KAS_KEY_SYSTEM_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry key create --kas "${KAS_REGISTRY_ID_BASE_KEY_TEST}" --key-id "${REGULAR_KEY_ID_FOR_BASE_TEST}" --algorithm rsa:2048 --mode local --wrapping-key "${WRAPPING_KEY}" --wrapping-key-id "wrapping-key-id" --json | jq -r '.key.id')
}

setup() {
  # invoke binary with credentials for base key commands
  run_otdfctl_base_key() {
    run sh -c "./otdfctl policy kas-registry key base $HOST $WITH_CREDS $*"
  }
}

teardown_file() {
  # Note: A key will be present still, due to a FK where we do
  # not allow keys to be deleted if they are currently set as the base key.
  delete_all_keys_in_kas "$KAS_REGISTRY_ID_BASE_KEY_TEST"

  unset HOST WITH_CREDS KAS_REGISTRY_ID_BASE_KEY_TEST KAS_NAME_BASE_KEY_TEST KAS_URI_BASE_KEY_TEST REGULAR_KEY_ID_FOR_BASE_TEST WRAPPING_KEY KAS_KEY_SYSTEM_ID
}

# --- get base key tests ---

@test "base-key: get (initially no base key should be set for a new KAS)" {
  run_otdfctl_base_key get
  assert_failure                              # Expecting failure or specific message indicating no base key
  assert_output --partial "No base key found" # Or similar error message
}

# --- set base key tests ---

@test "base-key: set by --key (uuid)" {
  run_otdfctl_base_key set --key "${KAS_KEY_SYSTEM_ID}" --json
  assert_success
  # Verify the new base key part of the response
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .new_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.algorithm)" 1
  # Verify previous base key is null or not present if this is the first set
  assert_equal "$(echo "$output" | jq -r .previous_base_key)" "null"
}

@test "base-key: set by --key(id) and --kas(id)" {
  run_otdfctl_base_key set --key "${REGULAR_KEY_ID_FOR_BASE_TEST}" --kas "${KAS_REGISTRY_ID_BASE_KEY_TEST}" --json
  assert_success
  # Verify the new base key part of the response
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .new_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.algorithm)" 1
}

@test "base-key: get (after setting a base key)" {
  run_otdfctl_base_key set --key "${KAS_KEY_SYSTEM_ID}" --json
  assert_success

  run_otdfctl_base_key get --json
  assert_success
  assert_equal "$(echo "$output" | jq -r .public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .public_key.algorithm)" 1
}

@test "base-key: set by --key(id) and --kas(name)" {
  run_otdfctl_base_key set --key "${REGULAR_KEY_ID_FOR_BASE_TEST}" --kas "${KAS_NAME_BASE_KEY_TEST}" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .new_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}" # KAS URI should remain the same for the KAS Name
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.algorithm)" 1
}

@test "base-key: set by --key(id) and --kas(uri)" {
  # This will set REGULAR_KEY_ID_FOR_BASE_TEST back as the base key
  run_otdfctl_base_key set --key "${REGULAR_KEY_ID_FOR_BASE_TEST}" --kas "${KAS_URI_BASE_KEY_TEST}" --json
  assert_success
  # Verify the new base key
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .new_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}" # KAS URI should remain the same for the KAS Name
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.algorithm)" 1
}

@test "base-key: set, get, and verify previous base key" {
  run_otdfctl_base_key set --key "${KAS_KEY_SYSTEM_ID}" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .new_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.algorithm)" 1

  run_otdfctl_base_key get --json
  assert_success
  assert_equal "$(echo "$output" | jq -r .public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .public_key.algorithm)" 1

  SECOND_KEY_ID_FOR_BASE_TEST="second-key-for-base-$(date +%s)"
  SECOND_KAS_KEY_SYSTEM_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry key create --kas "${KAS_REGISTRY_ID_BASE_KEY_TEST}" --key-id "${SECOND_KEY_ID_FOR_BASE_TEST}" --algorithm ec:secp256r1 --mode local --wrapping-key "${WRAPPING_KEY}" --wrapping-key-id "test-key" --json | jq -r '.key.id')

  run_otdfctl_base_key set --key "${SECOND_KAS_KEY_SYSTEM_ID}" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.kid)" "${SECOND_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .new_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .new_base_key.public_key.algorithm)" 3
  # Verify previous base key
  assert_equal "$(echo "$output" | jq -r .previous_base_key.public_key.kid)" "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_equal "$(echo "$output" | jq -r .previous_base_key.kas_uri)" "${KAS_URI_BASE_KEY_TEST}"
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" ""
  assert_not_equal "$(echo "$output" | jq -r .new_base_key.public_key.pem)" "null"
  assert_equal "$(echo "$output" | jq -r .previous_base_key.public_key.algorithm)" 1
}

@test "base-key: set (missing kas identifier)" {
  run_otdfctl_base_key set --key "${REGULAR_KEY_ID_FOR_BASE_TEST}"
  assert_failure
  assert_output --partial "Flag '--kas' is required"
}

@test "base-key: set (missing key identifier: id or keyId)" {
  run_otdfctl_base_key set --kas "${KAS_REGISTRY_ID_BASE_KEY_TEST}"
  assert_failure
  assert_output --partial "Flag '--key' is required"
}

@test "base-key: set (using non-existent keyId)" {
  NON_EXISTENT_KEY_ID="this-key-does-not-exist-12345"
  run_otdfctl_base_key set --key "${NON_EXISTENT_KEY_ID}" --kas "${KAS_REGISTRY_ID_BASE_KEY_TEST}"
  assert_failure
  # The exact error message might depend on the backend implementation
  assert_output --partial "not_found" # Or a more specific "key not found" error
}

@test "base-key: set (using non-existent kasId)" {
  NON_EXISTENT_KAS_ID="a1b2c3d4-e5f6-7890-1234-567890abcdef"
  run_otdfctl_base_key set --key "${REGULAR_KEY_ID_FOR_BASE_TEST}" --kas "${NON_EXISTENT_KAS_ID}"
  assert_failure
  assert_output --partial "not_found" # Or a more specific "KAS not found" error
}
