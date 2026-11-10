#!/usr/bin/env bats

# Tests for namespaces
load "${BATS_LIB_PATH}/bats-support/load.bash"
load "${BATS_LIB_PATH}/bats-assert/load.bash"
load "otdfctl-utils.sh"

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  # Create the namespace to be used by other tests

  export NS_NAME="creating-test-ns.net"
  export NS_NAME_UPDATE="updated-test-ns.net"
  export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$NS_NAME" --json | jq -r '.id')
  export NS_ID_FLAG="--id $NS_ID"

  export KAS_URI="https://test-kas-for-namespace.com"
  export KAS_REG_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --uri "$KAS_URI" --json | jq -r '.id')
  # Generate a valid RSA public key and base64 encode (single-line)
  export PEM_B64=$(openssl genrsa 2048 2>/dev/null | openssl rsa -pubout 2>/dev/null | base64 | tr -d '\n')
  export KAS_KEY_ID="test-key-for-namespace"
  export KAS_KEY_SYSTEM_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry key create --kas "$KAS_REG_ID" --key-id "$KAS_KEY_ID" --algorithm "rsa:2048" --mode "public_key" --public-key-pem "${PEM_B64}" --json | jq -r '.key.id')
  export PEM=$(echo "$PEM_B64" | base64 -d)
}

setup() {
  # invoke binary with credentials
  run_otdfctl_ns() {
    run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes namespaces $*"
  }
}

teardown_file() {
  ./otdfctl $HOST $WITH_CREDS policy attributes namespace unsafe delete --id "$NS_ID" --force

  delete_all_keys_in_kas "$KAS_REG_ID"
  delete_kas_registry "$KAS_REG_ID"
  
  # clear out all test env vars
  unset HOST WITH_CREDS NS_NAME NS_FQN NS_ID NS_ID_FLAG KAS_REG_ID KAS_KEY_ID KAS_URI PEM_B64 PEM KAS_KEY_SYSTEM_ID
}

@test "Create a namespace - Good" {
  run_otdfctl_ns create --name throwaway.test
  assert_output --partial "SUCCESS"
  assert_line --regexp "Name.*throwaway.test"
  assert_output --partial "Id"
  assert_output --partial "Created At"
  assert_line --partial "Updated At"

  # cleanup
  created_id=$(echo "$output" | grep Id | awk -F'│' '{print $3}' | xargs)
  run_otdfctl_ns unsafe delete --id $created_id --force
}

@test "Create a namespace - Bad" {
  # bad namespace names
  run_otdfctl_ns create --name no_domain_extension
  assert_failure
  run_otdfctl_ns create --name -first-char-hyphen.co
  assert_failure
  run_otdfctl_ns create --name last-char-hyphen-.co
  assert_failure

  # missing flag
  run_otdfctl_ns create
  assert_failure
  assert_output --partial "Flag '--name' is required"

  # conflict
  run_otdfctl_ns create -n "$NS_NAME"
  assert_failure
  assert_output --partial "already_exists"
}

@test "Get a namespace - Good" {
  run_otdfctl_ns get "$NS_ID_FLAG"
  assert_success
  assert_line --regexp "Id.*$NS_ID"
  assert_line --regexp "Name.*$NS_NAME"

  run_otdfctl_ns get "$NS_ID_FLAG" --json
  assert_success
  [ "$(echo "$output" | jq -r '.id')" = "$NS_ID" ]
  [ "$(echo "$output" | jq -r '.name')" = "$NS_NAME" ]
}

@test "Get a namespace - Bad" {
  run_otdfctl_ns get
  assert_failure
  assert_output --partial "Flag '--id' is required"

  run_otdfctl_ns get --id 'example.com'
  assert_failure
  assert_output --partial "Flag '--id' received value 'example.com' must be a valid UUID"

  run_otdfctl_ns get --id 'demo.com' --json
  assert_failure
  assert_output --partial "Flag '--id' received value 'demo.com' must be a valid UUID"
}

@test "List namespaces - when active" {
  run_otdfctl_ns list --json
  echo $output | jq --arg id "$NS_ID" '.namespaces[] | select(.id == $id)'
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state inactive --json
  refute_output --partial "$NS_ID"
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state active
  assert_output --partial "$NS_ID"
  assert_output --partial "Total"
  assert_line --regexp "Current Offset.*0"
}

@test "Update namespace - Safe" {
  # extend labels
  run_otdfctl_ns update "$NS_ID_FLAG" -l key=value --label test=true
  assert_success
  assert_line --regexp "Id.*$NS_ID"
  assert_line --regexp "Name.*$NS_NAME"
  assert_line --regexp "Labels.*key: value"
  assert_line --regexp "Labels.*test: true"

  # force replace labels
  run_otdfctl_ns update "$NS_ID_FLAG" -l key=other --force-replace-labels
  assert_success
  assert_line --regexp "Id.*$NS_ID"
  assert_line --regexp "Name.*$NS_NAME"
  assert_line --regexp "Labels.*key: other"
  refute_output --regexp "Labels.*key: value"
  refute_output --regexp "Labels.*test: true"
}

@test "Update namespace - Unsafe" {
  run_otdfctl_ns unsafe update "$NS_ID_FLAG" -n "$NS_NAME_UPDATE" --force
  assert_success
  assert_line --regexp "Id.*$NS_ID"
  run_otdfctl_ns get "$NS_ID_FLAG"
  assert_line --regexp "Name.*$NS_NAME_UPDATE"
  refute_output --regexp "Name.*$NS_NAME"
}

@test "Assign/Remove KAS key from namespace - With Namespace ID" {
  run_otdfctl_ns key assign --namespace "$NS_ID" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.namespace_id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.key_id')" "$KAS_KEY_SYSTEM_ID"

  run_otdfctl_ns get --id "$NS_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_uri')" "$KAS_URI"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_id')" "$KAS_REG_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.kid')" "$KAS_KEY_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.pem')" "$PEM"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.algorithm')" 1

  run_otdfctl_ns key remove --namespace "$NS_ID" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success

  run_otdfctl_ns get --id "$NS_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0
}

@test "Assign/Remove KAS key from namespace - With Namespace FQN" {
  run_otdfctl_ns get --id "$NS_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0
  NS_FQN=$(echo "$output" | jq -r '.fqn')

  run_otdfctl_ns key assign --namespace "$NS_FQN" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.namespace_id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.key_id')" "$KAS_KEY_SYSTEM_ID"

  run_otdfctl_ns get --id "$NS_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_uri')" "$KAS_URI"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_id')" "$KAS_REG_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.kid')" "$KAS_KEY_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.pem')" "$PEM"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.algorithm')" 1

  run_otdfctl_ns key remove --namespace "$NS_ID" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success

  run_otdfctl_ns get --id "$NS_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$NS_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0
}

@test "KAS key assignment error handling - namespace" {
  # Test with non-existent namespace ID
  run_otdfctl_ns key assign --namespace "00000000-0000-0000-0000-000000000000" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_failure
  assert_output --partial "ERROR"

  # Test with missing required flags
  run_otdfctl_ns key assign --namespace "$NS_ID"
  assert_failure
  assert_output --partial "Flag '--key-id' is required"

  run_otdfctl_ns key assign --key-id "$KAS_KEY_SYSTEM_ID"
  assert_failure
  assert_output --partial "Flag '--namespace' is required"
}

@test "Deactivate namespace" {
  run_otdfctl_ns deactivate "$NS_ID_FLAG" --force
  assert_success
  assert_line --regexp "Id.*$NS_ID"
  assert_line --regexp "Name.*$NS_NAME_UPDATE"
}

@test "List namespaces - when inactive" {
  run_otdfctl_ns list --json
  echo $output | jq --arg id "$NS_ID" '.namespaces[] | select(.id == $id)'
  assert_not_equal $(echo $output | jq '.pagination') "null"

  # json
  run_otdfctl_ns list --state inactive --json
  echo $output | assert_output --partial "$NS_ID"
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state active --json
  echo $output | refute_output --partial "$NS_ID"
  assert_not_equal $(echo $output | jq '.pagination') "null"
  # table
  run_otdfctl_ns list --state inactive
  echo $output | assert_output --partial "$NS_ID"

  run_otdfctl_ns list --state active
  echo $output | refute_output --partial "$NS_ID"
}

@test "Unsafe reactivate namespace" {
  run_otdfctl_ns unsafe reactivate "$NS_ID_FLAG" --force
  assert_success
  assert_line --regexp "Id.*$NS_ID"
}

@test "List namespaces - when reactivated" {
  run_otdfctl_ns list --json
  echo $output | jq --arg id "$NS_ID" '.namespaces[] | select(.id == $id)'
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state inactive --json
  echo $output | refute_output --partial "$NS_ID"
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state active
  echo $output | assert_output --partial "$NS_ID"
}

@test "Unsafe delete namespace" {
  run_otdfctl_ns unsafe delete "$NS_ID_FLAG" --force
  assert_success
  assert_line --regexp "Id.*$NS_ID"
  assert_line --regexp "Name.*$NS_NAME_UPDATE"
}

@test "List namespaces - when deleted" {
  run_otdfctl_ns list --json
  echo $output | refute_output --partial "$NS_ID"
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state inactive --json
  echo $output | refute_output --partial "$NS_ID"
  assert_not_equal $(echo $output | jq '.pagination') "null"

  run_otdfctl_ns list --state active
  echo $output | refute_output --partial "$NS_ID"
}
