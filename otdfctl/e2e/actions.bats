#!/usr/bin/env bats

# Tests for actions

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'
    export ACTION_NAMESPACE_NAME='test-act.org'
    export ACTION_NAMESPACE="https://$ACTION_NAMESPACE_NAME"
    # create namespace first (needed for action creation)
    export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name "$ACTION_NAMESPACE_NAME" --json | jq -r '.id')
}

setup() {
    bats_load_library bats-support
    bats_load_library bats-assert

    # invoke binary with credentials
    run_otdfctl_action () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy actions $*"
    }
}

teardown_file() {
  # clear out all test env vars
  # remove the namespace and cascade delete attributes and values used in registered resource values tests
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_ID" --force
  unset HOST WITH_CREDS ACTION_NAMESPACE ACTION_NAMESPACE_NAME NS_ID
}


@test "Create a new custom action - Good" {
  # with a namespace
  run_otdfctl_action create --name test_action_create_namespaced --namespace "$ACTION_NAMESPACE"
    assert_output --partial "SUCCESS"
    assert_line --regexp "Name.*test_action_create_namespaced"
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"
    assert_output --partial "Id"
    assert_output --partial "Created At"
    assert_line --partial "Updated At"

  # cleanup
  created_id=$(echo "$output" | grep Id | awk -F'│' '{print $3}' | xargs)
  run_otdfctl_action delete --id $created_id --force

  # without a namespace (should default to un-namespaced)
  run_otdfctl_action create --name test_action_create
    assert_output --partial "SUCCESS"
    assert_line --regexp "Name.*test_action_create"
    assert_output --partial "Id"
    assert_output --partial "Created At"
    assert_line --partial "Updated At"
    # ensure namespace is empty for un-namespaced actions
    refute_line --regexp "Namespace.*$ACTION_NAMESPACE"

  created_id=$(echo "$output" | grep Id | awk -F'│' '{print $3}' | xargs)
  run_otdfctl_action delete --id $created_id --force
}

@test "Create a new action - Bad" {
  # bad action names
    run_otdfctl_action create --name ends_underscored_ --namespace "$ACTION_NAMESPACE"
        assert_failure
    run_otdfctl_action create --name -first-char-hyphen --namespace "$ACTION_NAMESPACE"
        assert_failure
    run_otdfctl_action create --name inval!d.chars --namespace "$ACTION_NAMESPACE"
        assert_failure

  # missing flag
    run_otdfctl_action create --namespace "$ACTION_NAMESPACE"
        assert_failure
        assert_output --partial "Flag '--name' is required"

    # TODO: re-enable when namespace is required
    # run_otdfctl_action create --name no_namespace
    #     assert_failure
    #     assert_output --partial "Flag '--namespace' is required"
  
  # conflict
    run_otdfctl_action create -n "read" --namespace "$ACTION_NAMESPACE"
        assert_failure
        assert_output --partial "intended action would violate a restriction"
    
    run_otdfctl_action create -n "read"
        assert_failure
        assert_output --partial "intended action would violate a restriction"

  # duplicate custom action
    run_otdfctl_action create --name test_action_conflict --namespace "$ACTION_NAMESPACE" --json
        assert_success
    conflict_action_id=$(echo "$output" | jq -er '.id')
      assert_success
    [ -n "$conflict_action_id" ]

    run_otdfctl_action create --name test_action_conflict --namespace "$ACTION_NAMESPACE"
        assert_failure
        assert_output --partial "already_exists"

  # cleanup
    run_otdfctl_action delete --id "$conflict_action_id" --force
}

@test "Get an action - Good" {
  run_otdfctl_action get --name "read" --namespace "$ACTION_NAMESPACE"
    assert_success
    assert_line --partial "Id"
    assert_line --regexp "Name.*read"
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"

  # get by name to retrieve the ID
  UPDATE_ACTION_ID=$(./otdfctl policy actions get --name update --namespace "$ACTION_NAMESPACE" --json $HOST $WITH_CREDS | jq -r '.id')

  # ensure getting by id does not require namespace
  run_otdfctl_action get --id "$UPDATE_ACTION_ID" --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$UPDATE_ACTION_ID" ]
    [ "$(echo "$output" | jq -r '.name')" = "update" ]

  # ensure you can use the namespace id instead of the fqn
  run_otdfctl_action get --name "read" --namespace "$NS_ID"
    assert_success
    assert_line --partial "Id"
    assert_line --regexp "Name.*read"
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"

  # ensure get without namespace still works for un-namespaced actions
  run_otdfctl_action get --name "read"
    assert_success
    assert_line --partial "Id"
    assert_line --regexp "Name.*read"
    refute_line --regexp "Namespace.*$ACTION_NAMESPACE"
}

@test "Get an action - Bad" {
  run_otdfctl_action get
    assert_failure
    assert_output --partial "Either 'id' or 'name' must be provided"

  run_otdfctl_action get --id 'testing_get'
    assert_failure
    assert_output --partial "must be a valid UUID"

  # TODO: re-enable when namespace is required
  # run_otdfctl_action get --name 'testing_get'
  #   assert_failure
  #   assert_output --partial "namespace' must be provided when using 'name'"
}

@test "List actions" {
  run_otdfctl_action create --name test_action_list_namespaced --namespace "$ACTION_NAMESPACE" --json
  assert_success
  created_id=$(echo "$output" | jq -r '.id')
  run_otdfctl_action create --name test_action_list_unnamespaced --json
  assert_success
  created_id_2=$(echo "$output" | jq -r '.id')

  run_otdfctl_action list --namespace "$ACTION_NAMESPACE"
    assert_output --partial "Namespace"
    assert_output --partial "$ACTION_NAMESPACE"
    assert_output --partial "create"
    assert_output --partial "read"
    assert_output --partial "update"
    assert_output --partial "delete"
    assert_output --partial "Total"
    assert_line --regexp "Current Offset.*0"
    assert_output --partial "test_action_list_namespaced"
    refute_output --partial "test_action_list_unnamespaced"
  
  run_otdfctl_action list --namespace "$ACTION_NAMESPACE" --json
  assert_success
  assert_not_equal $(echo "$output" | jq -r 'pagination') "null"
  assert_output --partial "create"
  assert_output --partial "read"
  assert_output --partial "update"
  assert_output --partial "delete"
  total=$(echo "$output" | jq -r '.pagination.total')
  [[ "$total" -ge 1 ]]

  # listing without namespace should succeed and should include both namespaced and un-namespaced actions (namespace field should be empty for un-namespaced actions)
  run_otdfctl_action list
    assert_output --partial "create"
    assert_output --partial "read"
    assert_output --partial "update"
    assert_output --partial "delete"
    assert_output --partial "Total"
    assert_line --regexp "Current Offset.*0"
    assert_output --partial "test_action_list_namespaced"
    assert_output --partial "test_action_list_unnamespaced"

  run_otdfctl_action delete --id $created_id --force
  run_otdfctl_action delete --id $created_id_2 --force
}

@test "Update action" {
  ACTION_TO_UPDATE=$(./otdfctl policy actions create --name testing_updation --namespace "$ACTION_NAMESPACE" $HOST $WITH_CREDS --json | jq -r '.id')
  # extend labels
  run_otdfctl_action update --id "$ACTION_TO_UPDATE" -l key=value --label test=true
    assert_success
    assert_line --regexp "Id.*$ACTION_TO_UPDATE"
    assert_line --regexp "Name.*testing_updation"
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"
    assert_line --regexp "Labels.*key: value"
    assert_line --regexp "Labels.*test: true"

  # force replace labels
  run_otdfctl_action update --id "$ACTION_TO_UPDATE" -l key=other --force-replace-labels
    assert_success
    assert_line --regexp "Id.*$ACTION_TO_UPDATE"
    assert_line --regexp "Name.*testing_updation"
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"
    assert_line --regexp "Labels.*key: other"
    refute_output --regexp "Labels.*key: value"
    refute_output --regexp "Labels.*test: true"
    refute_output --regexp "Labels.*test: true"

  # renamed
  run_otdfctl_action update --id "$ACTION_TO_UPDATE" --name updated_action_in_test
    assert_success
    assert_line --regexp "Id.*$ACTION_TO_UPDATE"
    assert_line --regexp "Name.*updated_action_in_test"
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"
    refute_output --regexp "Name.*testing_updation"

  # clean up
  run_otdfctl_action delete --id "$ACTION_TO_UPDATE" --force
}

@test "Delete action - bad" {
  STANDARD_ACTION=$(./otdfctl policy actions get --name update --namespace "$ACTION_NAMESPACE" $HOST $WITH_CREDS --json | jq -r '.id')
  run_otdfctl_action delete --id "$STANDARD_ACTION" --force
    assert_failure
}

@test "Delete action - good" {
  DELETABLE_ACTION=$(./otdfctl policy actions create --name testing-delete --namespace "$ACTION_NAMESPACE" $HOST $WITH_CREDS --json | jq -r '.id')
  run_otdfctl_action delete --id "$DELETABLE_ACTION" --force
    assert_success
    assert_line --regexp "Namespace.*$ACTION_NAMESPACE"
}
