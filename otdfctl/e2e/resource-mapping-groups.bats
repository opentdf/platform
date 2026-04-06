#!/usr/bin/env bats

# Tests for resource mapping groups

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'

    # Create two namespaced values to be used in other tests
        NS_NAME="resource-mapping-groups.io"
        export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$NS_NAME" --json | jq -r '.id')
        NS_NAME2="resource-mapping-groups-2.io"
        export NS2_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$NS_NAME2" --json | jq -r '.id')
        ATTR_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name attr1 --rule ANY_OF --json | jq -r '.id')
        # Name is prefixed with RMG to avoid conflicts across tests when running in parallel
        export RMG_VAL1_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes values create --attribute-id "$ATTR_ID" --value val1 --json | jq -r '.id')
    
    # Create a resource mapping group
        export RMG1_NAME="rmgrp-test"
        export RMG1_ID=$(./otdfctl $HOST $WITH_CREDS policy resource-mapping-groups create --namespace-id "$NS_ID" --name "$RMG1_NAME" --json | jq -r '.id')

    # Create a couple resource mappings to val1 - comma separated
        export RM1_TERMS="valueone,valuefirst,first,one"
        export RM1_ID=$(./otdfctl $HOST $WITH_CREDS policy resource-mappings create --attribute-value-id "$RMG_VAL1_ID" --terms "$RM1_TERMS" --group-id "$RMG1_ID" --json | jq -r '.id')
        export RM1_OTHER_TERMS="otherone,othervaluefirst,otherfirst,otherone"
        export RM1_OTHER_ID=$(./otdfctl $HOST $WITH_CREDS policy resource-mappings create --attribute-value-id "$RMG_VAL1_ID" --terms "$RM1_OTHER_TERMS" --group-id "$RMG1_ID" --json | jq -r '.id')
}

setup() {
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"

    # invoke binary with credentials
    run_otdfctl_rmg () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy resource-mapping-groups $*"
    }

}

teardown_file() {
    # remove the created namespace with all underneath upon test suite completion
    ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --force --id "$NS_ID"
    ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --force --id "$NS2_ID"

    unset HOST WITH_CREDS RMG_VAL1_ID NS_ID NS2_ID RM1_TERMS RM1_ID RM1_OTHER_TERMS RM1_OTHER_ID RMG1_NAME RMG1_ID
}

@test "Create resource mapping group" {
    # create with multiple terms flags instead of comma-separated
    run_otdfctl_rmg create --namespace-id "$NS_ID" --name rmgrp1
    assert_success
    assert_output --partial "rmgrp1"
    assert_line --regexp "Namespace Id.*$NS_ID"

    # ns id flag must be uuid
    run_otdfctl_rmg create --namespace-id "something" --name testing
    assert_failure
    assert_output --partial "must be a valid UUID"

    # name is required
    run_otdfctl_rmg create --namespace-id "$NS_ID"
    assert_failure
    assert_output --partial "Flag '--name' is required"
}

@test "Get resource mapping group" {
    # table
    run_otdfctl_rmg get --id "$RMG1_ID"
        assert_success
        assert_line --regexp "Id.*$RMG1_ID"
        assert_line --regexp "Namespace Id.*$NS_ID"
        assert_line --regexp "Name.*$RMG1_NAME"
    
    # json
    run_otdfctl_rmg get --id "$RMG1_ID" --json
        assert_success
        [ $(echo $output | jq -r '.id') = "$RMG1_ID" ]
        [ $(echo $output | jq -r '.namespace_id') = "$NS_ID" ]
        [ $(echo $output | jq -r '.name') = "$RMG1_NAME" ]
    
    # id required
    run_otdfctl_rmg get
        assert_failure
        assert_output --partial "is required"
    run_otdfctl_rmg get --id "test"
        assert_failure
        assert_output --partial "must be a valid UUID"
}

@test "Update a resource mapping group" {
    NEW_RMG_ID=$(./otdfctl $HOST $WITH_CREDS policy resource-mapping-groups create --namespace-id "$NS_ID" --name test-rsmg --json | jq -r '.id')
    
    # replace the terms
    run_otdfctl_rmg update --id "$NEW_RMG_ID" --name "new-rsmg-name"
        assert_success
        refute_output --partial "test-rsmg"
        assert_output --partial "new-rsmg-name"
        assert_output --partial "$NS_ID"

    # reassign the namespace being mapped
    run_otdfctl_rmg update --id "$NEW_RMG_ID" --namespace-id "$NS2_ID"
        assert_success
        refute_output --partial "test-rsmg"
        assert_output --partial "new-rsmg-name"
        refute_output --partial "$NS_ID"
        assert_output --partial "$NS2_ID"
}

@test "List resource mapping groups" {
    run_otdfctl_rmg list
        assert_success
        assert_output --partial "$RMG1_ID"
        assert_output --partial "$NS_ID"
        assert_output --partial "$RMG1_NAME"
        assert_output --partial "Total"
        assert_line --regexp "Current Offset.*0"
    
    run_otdfctl_rmg list --json
    assert_success
    [[ "$(echo "$output" | jq -r '.resource_mapping_groups | length')" -ge 1 ]]
    found_rmg=$(echo "$output" | jq -c --arg id "$RMG1_ID" '.resource_mapping_groups as $a | ($a | map(.id) | index($id)) as $i | $a[$i]')
    assert_equal "$(echo "$found_rmg" | jq -r '.id')" "$RMG1_ID"
    assert_equal "$(echo "$found_rmg" | jq -r '.name')" "$RMG1_NAME"
    [[ "$(echo "$output" | jq -r '.pagination.total')" -ge 1 ]]
    assert_equal "$(echo "$output" | jq -r '.pagination.current_offset')" "null"
    assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "null"
}

@test "Delete resource mapping group" {
    # --force to avoid indefinite hang waiting for confirmation
    run_otdfctl_rmg delete --id "$RMG1_ID" --force
        assert_success
        assert_line --regexp "Id.*$RMG1_ID"
        assert_line --regexp "Namespace Id.*$NS_ID"
        assert_line --regexp "Name.*$RMG1_NAME"
}
