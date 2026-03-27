#!/usr/bin/env bats

setup_file() {
  export CREDSFILE=creds.json
  echo -n '{"clientId":"opentdf","clientSecret":"secret"}' > $CREDSFILE
  export WITH_CREDS="--with-client-creds-file $CREDSFILE"
  export HOST='--host http://localhost:8080'
  export DEBUG_LEVEL="--log-level debug"
  export VALID_CONFIG='{"cached":"key"}'
  export BASE64_CONFIG="eyJjYWNoZWQiOiAia2V5In0="
}

setup() {
    if [ "$RUN_EXPERIMENTAL_TESTS" != "true" ]; then
        skip "Skipping experimental test"
    fi
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"

    # invoke binary with credentials
    run_otdfctl_key_pc () {
      run sh -c "./otdfctl policy keymanagement provider $HOST $WITH_CREDS $*"
    }
}

delete_pc_by_id() {
  run_otdfctl_key_pc delete --id "$1" --force
  assert_success
}

#########
# Create Provider Configuration
#########
@test "fail to create provider configuration without config" {
    run_otdfctl_key_pc create --name test-value
    assert_failure
    assert_output --partial "Flag '--config' is required"
}

@test "fail to create provider configuration without name" {
    run_otdfctl_key_pc create --config '{}'
    assert_failure
    assert_output --partial "Flag '--name' is required"
}

@test "fail to create provider configuration with invalid config" {
    run_otdfctl_key_pc create --name test-config --config test-value
    assert_failure
    assert_output --partial "invalid_argument"
}

@test "create provider configuration" {
    CONFIG_NAME="test-config"
    run_otdfctl_key_pc create --name "$CONFIG_NAME" --config '"$VALID_CONFIG"' --json
    assert_success
    assert_equal "$(echo "$output" | jq -r .name)" "$CONFIG_NAME"
    assert_equal "$(echo "$output" | jq -r .config_json)" "$BASE64_CONFIG"
    delete_pc_by_id "$(echo "$output" | jq -r .id)"
}

@test "get provider configuration by id" {
    CONFIG_NAME="test-config-2"
    run_otdfctl_key_pc create --name "$CONFIG_NAME" --config '"$VALID_CONFIG"' --json
    assert_success
    ID=$(echo "$output" | jq -r '.id')
    run_otdfctl_key_pc get --id "$ID" --json
    assert_success
    assert_equal "$(echo "$output" | jq -r .name)" "$CONFIG_NAME"
    assert_equal "$(echo "$output" | jq -r .config_json)" "$BASE64_CONFIG"
    delete_pc_by_id "$(echo "$output" | jq -r .id)"
 }


@test "get provider configuration by name" {
    CONFIG_NAME="test-config-3"
    run_otdfctl_key_pc create --name "$CONFIG_NAME" --config '"$VALID_CONFIG"' --json
    assert_success
    NAME=$(echo "$output" | jq -r '.name')
    run_otdfctl_key_pc get --name "$NAME" --json
    assert_success
    assert_equal "$(echo "$output" | jq -r .name)" "$CONFIG_NAME"
    assert_equal "$(echo "$output" | jq -r .config_json)" "$BASE64_CONFIG"
    delete_pc_by_id "$(echo "$output" | jq -r .id)"
}

@test "fail to get provider configuration - no required flags" {
     run_otdfctl_key_pc get
     assert_failure
}

@test "fail to get provider configuration with non-existent name" {
    run_otdfctl_key_pc get --name non-existent-config
    assert_failure
    assert_output --partial "Failed to get provider config: not_found"
}
@test "list provider configurations" {
    NAME="tst-config-4"
    run_otdfctl_key_pc create --name "$NAME" --config '"$VALID_CONFIG"' --manager "fake-manager" --json
    assert_success
    ID=$(echo "$output" | jq -r '.id')
    run_otdfctl_key_pc list --json
    assert_success
    assert_equal "$(echo "$output" | jq '.provider_configs | length')" "1"
    assert_equal "$(echo "$output" | jq '.pagination.total')" "1"
    run_otdfctl_key_pc list
        assert_output --partial "Total"
        assert_line --regexp "Current Offset.*0"
    delete_pc_by_id "$ID"
}
 
@test "update provider configuration - success" {
    NAME="test-config-5"
    UPDATED_NAME="test-config-5-updated"
    UPDATED_CONFIG='{"cached": "key-updated"}'
    BASE64_UPDATED_CONFIG='eyJjYWNoZWQiOiAia2V5LXVwZGF0ZWQifQ=='
    run_otdfctl_key_pc create --name "$NAME" --config '"$VALID_CONFIG"' --json
    assert_success
    ID=$(echo "$output" | jq -r '.id')
    run_otdfctl_key_pc update --id "$ID" --name "$UPDATED_NAME" --config "'$UPDATED_CONFIG'" --json
    assert_success
    assert_equal "$(echo "$output" | jq -r .id)" "$ID"
    assert_equal "$(echo "$output" | jq -r .name)" "$UPDATED_NAME"
    assert_equal "$(echo "$output" | jq -r .config_json)" "$BASE64_UPDATED_CONFIG"
    delete_pc_by_id "$ID"
}

@test "fail to update provider configuration - missing id" {
    run_otdfctl_key_pc update --name test-config
    assert_failure
    assert_output --partial "Flag '--id' is required"
}

@test "fail to update provider configuration - no optional flags" {
    NAME="test-config-6"
    run_otdfctl_key_pc create --name "$NAME" --config '"$VALID_CONFIG"' --json
    ID=$(echo "$output" | jq -r '.id')
    run_otdfctl_key_pc update --id "$ID"
    assert_failure
    assert_output --partial "At least one field (name, config, or metadata labels) must be updated"
    delete_pc_by_id "$ID"
}

@test "fail to update provider configuration - invalid config format" {
    NAME="test-config-7"
    run_otdfctl_key_pc create --name "$NAME" --config '"$VALID_CONFIG"' --json
    assert_success
    ID=$(echo "$output" | jq -r '.id')
    run_otdfctl_key_pc update --id "$ID" --config "{invalid: json}"
    assert_failure
    assert_output --partial "invalid_argument"
    delete_pc_by_id "$ID"
}
 
@test "delete provider configuration -- success" {
  NAME="test-config-8"  
  run_otdfctl_key_pc create --name "$NAME" --config '"$VALID_CONFIG"' --json
  ID=$(echo "$output" | jq -r '.id')
  run_otdfctl_key_pc delete --id "$ID" --force
  assert_success
}

@test "delete provider configuration fail -- no id" {
  run_otdfctl_key_pc delete
  assert_failure
  assert_output --partial "Flag '--id' is required"
}

@test "delete provider configuration fail -- no force" {
  NAME="test-config-9"
  run_otdfctl_key_pc create --name "$NAME" --config '"$VALID_CONFIG"' --json
  ID=$(echo "$output" | jq -r '.id')
  run_otdfctl_key_pc delete --id "$ID"
  assert_failure
  assert_output --partial "The '--force' flag is required for this operation"
  delete_pc_by_id "$ID"
}

teardown_file() {
  # clear out all test env vars
  unset HOST WITH_CREDS DEBUG_LEVEL VALID_CONFIG BASE64_CONFIG
}