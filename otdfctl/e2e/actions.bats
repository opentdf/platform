#!/usr/bin/env bats

# Tests for actions

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'
}

setup() {
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"

    # invoke binary with credentials
    run_otdfctl_action () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy actions $*"
    }
}

teardown_file() {
  # clear out all test env vars
  unset HOST WITH_CREDS
}

@test "Create a new custom action - Good" {
  run_otdfctl_action create --name test_action_create
    assert_output --partial "SUCCESS"
    assert_line --regexp "Name.*test_action_create"
    assert_output --partial "Id"
    assert_output --partial "Created At"
    assert_line --partial "Updated At"

  # cleanup
  created_id=$(echo "$output" | grep Id | awk -F'│' '{print $3}' | xargs)
  run_otdfctl_action delete --id $created_id --force
}

@test "Create a new action - Bad" {
  # bad action names
    run_otdfctl_action create --name ends_underscored_
        assert_failure
    run_otdfctl_action create --name -first-char-hyphen
        assert_failure
    run_otdfctl_action create --name inval!d.chars
        assert_failure

  # missing flag
    run_otdfctl_action create
        assert_failure
        assert_output --partial "Flag '--name' is required"
  
  # conflict
    run_otdfctl_action create -n "read"
        assert_failure
        assert_output --partial "already_exists"
}

@test "Get an action - Good" {
  run_otdfctl_action get --name "read"
    assert_success
    assert_line --partial "Id"
    assert_line --regexp "Name.*read"

  # get by name to retrieve the ID
  UPDATE_ACTION_ID=$(./otdfctl policy actions get --name update --json $HOST $WITH_CREDS | jq -r '.id')

  run_otdfctl_action get --id "$UPDATE_ACTION_ID" --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$UPDATE_ACTION_ID" ]
    [ "$(echo "$output" | jq -r '.name')" = "update" ]
}

@test "Get an action - Bad" {
  run_otdfctl_action get
    assert_failure
    assert_output --partial "Either 'id' or 'name' must be provided"

  run_otdfctl_action get --id 'testing_get'
    assert_failure
    assert_output --partial "must be a valid UUID"
}

@test "List actions" {
  run_otdfctl_action list  
    assert_output --partial "create"
    assert_output --partial "read"
    assert_output --partial "update"
    assert_output --partial "delete"
    assert_output --partial "Total"
    assert_line --regexp "Current Offset.*0"
  
  run_otdfctl_action list --json
  assert_success
  assert_not_equal $(echo "$output" | jq -r 'pagination') "null"
  assert_output --partial "create"
  assert_output --partial "read"
  assert_output --partial "update"
  assert_output --partial "delete"
  total=$(echo "$output" | jq -r '.pagination.total')
  [[ "$total" -ge 1 ]]
}

@test "Update action" {
  ACTION_TO_UPDATE=$(./otdfctl policy actions create --name testing_updation $HOST $WITH_CREDS --json | jq -r '.id')
  # extend labels
  run_otdfctl_action update --id "$ACTION_TO_UPDATE" -l key=value --label test=true
    assert_success
    assert_line --regexp "Id.*$ACTION_TO_UPDATE"
    assert_line --regexp "Name.*testing_updation"
    assert_line --regexp "Labels.*key: value"
    assert_line --regexp "Labels.*test: true"

  # force replace labels
  run_otdfctl_action update --id "$ACTION_TO_UPDATE" -l key=other --force-replace-labels
    assert_success
    assert_line --regexp "Id.*$ACTION_TO_UPDATE"
    assert_line --regexp "Name.*testing_updation"
    assert_line --regexp "Labels.*key: other"
    refute_output --regexp "Labels.*key: value"
    refute_output --regexp "Labels.*test: true"
    refute_output --regexp "Labels.*test: true"

  # renamed
  run_otdfctl_action update --id "$ACTION_TO_UPDATE" --name updated_action_in_test
    assert_success
    assert_line --regexp "Id.*$ACTION_TO_UPDATE"
    assert_line --regexp "Name.*updated_action_in_test"
    refute_output --regexp "Name.*testing_updation"

  # clean up
  run_otdfctl_action delete --id "$ACTION_TO_UPDATE" --force
}

@test "Delete action - bad" {
  STANDARD_ACTION=$(./otdfctl policy actions get --name update $HOST $WITH_CREDS --json | jq -r '.id')
  run_otdfctl_action delete --id "$STANDARD_ACTION" --force
    assert_failure
}

@test "Delete action - good" {
  DELETABLE_ACTION=$(./otdfctl policy actions create --name testing-delete $HOST $WITH_CREDS --json | jq -r '.id')
  run_otdfctl_action delete --id "$DELETABLE_ACTION" --force
    assert_success
}
