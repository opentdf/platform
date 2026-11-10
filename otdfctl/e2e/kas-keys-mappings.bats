#!/usr/bin/env bats

# Tests listing key mappings

load "${BATS_LIB_PATH}/bats-support/load.bash"
load "${BATS_LIB_PATH}/bats-assert/load.bash"
load "otdfctl-utils.sh"

# Helper functions for otdfctl commands
run_otdfctl_key() {
  run sh -c "./otdfctl policy kas-registry key $HOST $WITH_CREDS $*"
}

run_otdfctl_kas_registry_create() {
  run sh -c "./otdfctl policy kas-registry create $HOST $WITH_CREDS $*"
}

run_otdfctl_namespace_create() {
  run sh -c "./otdfctl policy attributes namespaces create $HOST $WITH_CREDS $*"
}

run_otdfctl_attribute_create() {
  run sh -c "./otdfctl policy attributes create $HOST $WITH_CREDS $*"
}

run_otdfctl_value_create() {
  run sh -c "./otdfctl policy attributes values create $HOST $WITH_CREDS $*"
}

run_otdfctl_namespace_assign_key() {
  run sh -c "./otdfctl policy attributes namespaces key assign $HOST $WITH_CREDS $*"
}

run_otdfctl_attribute_assign_key() {
  run sh -c "./otdfctl policy attributes key assign $HOST $WITH_CREDS $*"
}

run_otdfctl_value_assign_key() {
  run sh -c "./otdfctl policy attributes values key assign $HOST $WITH_CREDS $*"
}

run_otdfctl_namespace_remove_key() {
  run sh -c "./otdfctl policy attributes namespaces key remove $HOST $WITH_CREDS $*"
}

run_otdfctl_attribute_remove_key() {
  run sh -c "./otdfctl policy attributes key remove $HOST $WITH_CREDS $*"
}

run_otdfctl_value_remove_key() {
  run sh -c "./otdfctl policy attributes values key remove $HOST $WITH_CREDS $*"
}

run_otdfctl_value_delete() {
  run sh -c "./otdfctl policy attributes values unsafe delete --force $HOST $WITH_CREDS $*"
}

run_otdfctl_attribute_delete() {
  run sh -c "./otdfctl policy attributes unsafe delete --force $HOST $WITH_CREDS $*"
}

run_otdfctl_namespace_delete() {
  run sh -c "./otdfctl policy namespaces unsafe delete --force $HOST $WITH_CREDS $*"
}

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'
  export KAS_URI="https://test-kas-for-mappings.com"
  export KAS_NAME="kas-registry-for-mappings-test"
  # Generate valid public keys for different algorithms and base64 encode (single-line)
  export PEM_B64_RSA_2048=$(openssl genrsa 2048 2>/dev/null | openssl rsa -pubout 2>/dev/null | base64 | tr -d '\n')
  export PEM_B64_EC_P256=$(openssl ecparam -name prime256v1 -genkey 2>/dev/null | openssl ec -pubout 2>/dev/null | base64 | tr -d '\n')
  export PEM_B64_RSA_4096=$(openssl genrsa 4096 2>/dev/null | openssl rsa -pubout 2>/dev/null | base64 | tr -d '\n')

  run_otdfctl_kas_registry_create --name $KAS_NAME --uri "$KAS_URI" --json
  assert_success
  export KAS_REGISTRY_ID=$(echo "$output" | jq -r '.id')

  # Create three keys
  export KEY_ID_1=$(generate_key_id)
  run_otdfctl_key create --kas "${KAS_REGISTRY_ID}" --key-id "${KEY_ID_1}" --algorithm "rsa:2048" --mode "public_key" --public-key-pem "${PEM_B64_RSA_2048}" --json
  assert_success
  export SYSTEM_KEY_ID_1=$(echo "$output" | jq -r '.key.id')

  export KEY_ID_2=$(generate_key_id)
  run_otdfctl_key create --kas "${KAS_REGISTRY_ID}" --key-id "${KEY_ID_2}" --algorithm "ec:secp256r1" --mode "public_key" --public-key-pem "${PEM_B64_EC_P256}" --json
  assert_success
  export SYSTEM_KEY_ID_2=$(echo "$output" | jq -r '.key.id')

  export KEY_ID_3=$(generate_key_id)
  run_otdfctl_key create --kas "${KAS_REGISTRY_ID}" --key-id "${KEY_ID_3}" --algorithm "rsa:4096" --mode "public_key" --public-key-pem "${PEM_B64_RSA_4096}" --json
  assert_success
  export SYSTEM_KEY_ID_3=$(echo "$output" | jq -r '.key.id')

  # Create a namespace, attribute, and value for testing assignments
  export NAMESPACE_NAME="test-namespace-for-mappings.com"
  run_otdfctl_namespace_create --name "${NAMESPACE_NAME}" --json
  assert_success
  export NAMESPACE_ID=$(echo "$output" | jq -r '.id')

  export ATTRIBUTE_NAME=$(generate_kas_name)
  run_otdfctl_attribute_create --name "${ATTRIBUTE_NAME}" --namespace "${NAMESPACE_ID}" --rule ALL_OF --json
  assert_success
  export ATTRIBUTE_ID=$(echo "$output" | jq -r '.id')

  export VALUE_NAME=$(generate_kas_name)
  run_otdfctl_value_create --value "${VALUE_NAME}" --attribute-id "${ATTRIBUTE_ID}" --json
  assert_success
  export VALUE_ID=$(echo "$output" | jq -r '.id')

  # Assign all three keys to the namespace, attribute, and value
  run_otdfctl_namespace_assign_key --namespace "${NAMESPACE_ID}" --key-id "${SYSTEM_KEY_ID_1}"
  assert_success
  run_otdfctl_namespace_assign_key --namespace "${NAMESPACE_ID}" --key-id "${SYSTEM_KEY_ID_2}"
  assert_success
  run_otdfctl_namespace_assign_key --namespace "${NAMESPACE_ID}" --key-id "${SYSTEM_KEY_ID_3}"
  assert_success

  run_otdfctl_attribute_assign_key --attribute "${ATTRIBUTE_ID}" --key-id "${SYSTEM_KEY_ID_1}"
  assert_success
  run_otdfctl_attribute_assign_key --attribute "${ATTRIBUTE_ID}" --key-id "${SYSTEM_KEY_ID_2}"
  assert_success
  run_otdfctl_attribute_assign_key --attribute "${ATTRIBUTE_ID}" --key-id "${SYSTEM_KEY_ID_3}"
  assert_success

  run_otdfctl_value_assign_key --value "${VALUE_ID}" --key-id "${SYSTEM_KEY_ID_1}"
  assert_success
  run_otdfctl_value_assign_key --value "${VALUE_ID}" --key-id "${SYSTEM_KEY_ID_2}"
  assert_success
  run_otdfctl_value_assign_key --value "${VALUE_ID}" --key-id "${SYSTEM_KEY_ID_3}"
  assert_success
}

setup() {
  # No setup specific to individual tests needed here currently
  : # No-op
}

teardown_file() {
  # Unassign the keys
  run_otdfctl_namespace_remove_key --namespace "${NAMESPACE_ID}" --key-id "${SYSTEM_KEY_ID_1}"
  run_otdfctl_namespace_remove_key --namespace "${NAMESPACE_ID}" --key-id "${SYSTEM_KEY_ID_2}"
  run_otdfctl_namespace_remove_key --namespace "${NAMESPACE_ID}" --key-id "${SYSTEM_KEY_ID_3}"
  run_otdfctl_attribute_remove_key --attribute "${ATTRIBUTE_ID}" --key-id "${SYSTEM_KEY_ID_1}"
  run_otdfctl_attribute_remove_key --attribute "${ATTRIBUTE_ID}" --key-id "${SYSTEM_KEY_ID_2}"
  run_otdfctl_attribute_remove_key --attribute "${ATTRIBUTE_ID}" --key-id "${SYSTEM_KEY_ID_3}"
  run_otdfctl_value_remove_key --value "${VALUE_ID}" --key-id "${SYSTEM_KEY_ID_1}"
  run_otdfctl_value_remove_key --value "${VALUE_ID}" --key-id "${SYSTEM_KEY_ID_2}"
  run_otdfctl_value_remove_key --value "${VALUE_ID}" --key-id "${SYSTEM_KEY_ID_3}"

  # Delete the value, attribute, and namespace
  run_otdfctl_value_delete --id "${VALUE_ID}"
  run_otdfctl_attribute_delete --id "${ATTRIBUTE_ID}"
  run_otdfctl_namespace_delete --id "${NAMESPACE_ID}"

  delete_all_keys_in_kas "$KAS_REGISTRY_ID"
  delete_kas_registry "$KAS_REGISTRY_ID"

  unset HOST WITH_CREDS KAS_REGISTRY_ID KAS_NAME KAS_URI PEM_B64 KEY_ID_1 SYSTEM_KEY_ID_1 KEY_ID_2 SYSTEM_KEY_ID_2 KEY_ID_3 SYSTEM_KEY_ID_3 NAMESPACE_ID NAMESPACE_NAME ATTRIBUTE_ID ATTRIBUTE_NAME VALUE_ID VALUE_NAME
}

# Helper function to generate a unique key ID
generate_key_id() {
  local length="${1:-8}"

  if [ ! -c /dev/urandom ]; then
    echo "Error: /dev/urandom not found. Cannot generate random string." >&2
    return 1
  fi
  key_id=$(LC_ALL=C tr </dev/urandom -dc 'A-Za-z0-9' 2>/dev/null | head -c "${length}")
  echo "$key_id"
}

generate_kas_name() {
  local length="${1:-6}"

  if [ ! -c /dev/urandom ]; then
    echo "Error: /dev/urandom not found. Cannot generate random string." >&2
    return 1
  fi
  kas_name=$(LC_ALL=C tr </dev/urandom -dc 'A-Za-z0-9' 2>/dev/null | head -c "${length}")
  echo "$kas_name"
}

format_kas_name_as_uri() {
  local input="$1"
  echo "http://${input}.org"
}

# Helper function to assert key mapping details
assert_key_mapping_details() {
    local key_id="$1"
    assert_equal "$(echo "$output" | jq -r '.key_mappings | length')" "1"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].kid')" "${key_id}"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].kas_uri')" "${KAS_URI}"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].namespace_mappings | length')" "1"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].attribute_mappings | length')" "1"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].value_mappings | length')" "1"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].namespace_mappings[0].id')" "${NAMESPACE_ID}"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].attribute_mappings[0].id')" "${ATTRIBUTE_ID}"
    assert_equal "$(echo "$output" | jq -r '.key_mappings.[0].value_mappings[0].id')" "${VALUE_ID}"
}

@test "kas-keys-mappings: list key mappings for a specific key by kas id" {
  run_otdfctl_key list-mappings --kas "${KAS_REGISTRY_ID}" --key-id "${KEY_ID_1}" --json
  assert_success
  assert_key_mapping_details "${KEY_ID_1}"
}

@test "kas-keys-mappings: list key mappings for a specific key by kas name" {
  run_otdfctl_key list-mappings --kas "${KAS_NAME}" --key-id "${KEY_ID_1}" --json
  assert_success
  assert_key_mapping_details "${KEY_ID_1}"
}

@test "kas-keys-mappings: list key mappings for a specific key by kas uri" {
    run_otdfctl_key list-mappings --kas "${KAS_URI}" --key-id "${KEY_ID_1}" --json
    assert_success
    assert_key_mapping_details "${KEY_ID_1}"
}

@test "kas-keys-mappings: list key mappings with pagination" {
  run_otdfctl_key list-mappings --json --limit 1 --offset 0
  assert_success
  assert_key_mapping_details "${KEY_ID_1}"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" "3"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "1"

  run_otdfctl_key list-mappings --json --limit 1 --offset 1
  assert_success
  assert_key_mapping_details "${KEY_ID_2}"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" "3"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "2"

  run_otdfctl_key list-mappings --json --limit 1 --offset 2
  assert_success
  assert_key_mapping_details "${KEY_ID_3}"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" "3"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "null"
}

@test "kas-keys-mappings: list key mappings - required together are missing" {
  run_otdfctl_key list-mappings --key-id "nonexistent-key" --json
  assert_failure
  assert_output --partial "--kas"

  run_otdfctl_key list-mappings --kas "${KAS_NAME}" --json
  assert_failure
  assert_output --partial "--kas"
}

@test "kas-keys-mappings: list key mappings - mutually exclusive flags" {
  run_otdfctl_key list-mappings --kas "${KAS_NAME}" --key-id "nonexistent-key" --id "${KEY_ID_1}" --json
  assert_failure
  assert_output --partial "Error: if any flags in the group [kas id] are set none of the others can be; [id kas] were all set"
}




