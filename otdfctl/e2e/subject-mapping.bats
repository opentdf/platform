#!/usr/bin/env bats

# Tests for subject mappings

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'

    # Create two namespaced values to be used in other tests
    export NS_NAME="subject-mappings-test.net"
    export NS_FQN="https://$NS_NAME"
    export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$NS_NAME" --json | jq -r '.id')
    ATTR_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name attr1 --rule ANY_OF --json | jq -r '.id')
    # Names prefixed with SM to avoid conflicts across tests when running in parallel
    export SM_VAL1_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes values create --attribute-id "$ATTR_ID" --value val1 --json | jq -r '.id')
    export SM_VAL2_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes values create --attribute-id "$ATTR_ID" --value value2 --json | jq -r '.id')

    export SCS_1='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["ShinyThing"],"subject_external_selector_value":".team.name"},{"operator":2,"subject_external_values":["marketing"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
    export SCS_2='[{"condition_groups":[{"conditions":[{"operator":2,"subject_external_values":["CoolTool","RadService"],"subject_external_selector_value":".team.name"},{"operator":1,"subject_external_values":["sales"],"subject_external_selector_value":".org.name"}],"boolean_operator":2}]}]'

    export ACTION_READ_NAME='read'
    export ACTION_READ_ID=$(./otdfctl $HOST $WITH_CREDS policy actions get --name "$ACTION_READ_NAME" --json | jq -r '.id')
    export ACTION_CREATE_NAME='create'
    export ACTION_CREATE_ID=$(./otdfctl $HOST $WITH_CREDS policy actions get --name "$ACTION_CREATE_NAME" --json | jq -r '.id')
}

setup() {
    bats_load_library bats-support
    bats_load_library bats-assert

    # invoke binary with credentials
    run_otdfctl_sm () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy subject-mappings $*"
    }

}

teardown_file() {
    # remove the created namespace with all underneath upon test suite completion
    ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --force --id "$NS_ID"

    unset HOST WITH_CREDS SM_VAL1_ID SM_VAL2_ID NS_ID NS_FQN NS_NAME SCS_1 SCS_2
}

@test "Create subject mapping" {
    # create with simultaneous new SCS
    run ./otdfctl $HOST $WITH_CREDS policy subject-mappings create -a "$SM_VAL1_ID" --action "$ACTION_CREATE_NAME" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_2"
        assert_success
        assert_output --partial "Namespace"
        assert_output --partial "Subject Condition Set: Id"
        assert_output --partial ".team.name"
        assert_line --regexp "Attribute Value Id.*$SM_VAL1_ID"

    # scs is required
    run_otdfctl_sm create --attribute-value-id "$SM_VAL2_ID" --action "$ACTION_CREATE_NAME"
    assert_failure
    assert_output --partial "At least one Subject Condition Set flag [--subject-condition-set-id, --subject-condition-set-new] must be provided"

    # action is required
    run_otdfctl_sm create -a "$SM_VAL1_ID" --subject-condition-set-new "$SCS_2"
    assert_failure
    assert_output --partial "At least one Action [--action] is required"
}

@test "Match subject mapping" {
    # create with simultaneous new SCS
    NEW_SCS='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["sales"],"subject_external_selector_value":".department"}],"boolean_operator":2}]}]'
    NEW_SM_ID=$(./otdfctl $HOST $WITH_CREDS policy subject-mappings create -a "$SM_VAL2_ID" --action "$ACTION_READ_NAME" --subject-condition-set-new "$NEW_SCS" --json | jq -r '.id')

    run_otdfctl_sm match -x '.department'
    assert_success
    assert_output --partial "$NEW_SM_ID"

    matched_subject='{"department":"any_department"}'
    run ./otdfctl policy sm match --subject "$matched_subject" $HOST $WITH_CREDS
    assert_success
    assert_output --partial "$NEW_SM_ID"

    # JWT includes 'department' in token claims
    run_otdfctl_sm match -s 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZXBhcnRtZW50Ijoibm93aGVyZV9zcGVjaWFsIn0.784uXYtfOv4tdM6JRgBMua4bBNDjUGbcr89QQKzCXfU'
    assert_success
    assert_output --partial "$NEW_SM_ID"

    run_otdfctl_sm match --selector '.not_found'
    assert_success
    refute_output --partial "$NEW_SM_ID"

    unmatched_subject='{"dept":"nope"}'
    run ./otdfctl policy sm match -s "$unmatched_subject" $HOST $WITH_CREDS
    assert_success
    refute_output --partial "$NEW_SM_ID"

    # JWT lacks 'department' in token claims
    run_otdfctl_sm match -s 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhYmMiOiJub3doZXJlX3NwZWNpYWwifQ.H39TXi1gYWRhXIRkfxFJwrZz42eE4y8V5BQX-mg8JAo'
    assert_success
    refute_output --partial "$NEW_SM_ID"
}

@test "Get subject mapping" {
    run ./otdfctl $HOST $WITH_CREDS policy sm create -a "$SM_VAL2_ID" --action "custom_sm_action_test" --subject-condition-set-new "$SCS_1" --json
    assert_success
    created=$(echo "$output" | jq -r '.id')
    scs_1_id=$(echo "$output" | jq -r '.subject_condition_set.id')
    assert_not_equal "$created" "null"
    assert_not_equal "$created" ""
    assert_not_equal "$scs_1_id" "null"
    assert_not_equal "$scs_1_id" ""

    # table
    run_otdfctl_sm get --id "$created"
        assert_success
        assert_line --regexp "Id.*$created"
        assert_output --partial "Namespace"
        assert_line --regexp "Attribute Value: Id.*$SM_VAL2_ID"
        assert_line --regexp "Attribute Value: Value.*value2"
        assert_line --regexp "Subject Condition Set: Id.*$scs_1_id"

    # json
    run_otdfctl_sm get --id "$created" --json
        assert_success
        [ "$(echo $output | jq -r '.id')" = "$created" ]
        [ "$(echo $output | jq -r '.attribute_value.id')" = "$SM_VAL2_ID" ]
        [ "$(echo $output | jq -r '.subject_condition_set.id')" = "$scs_1_id" ]
        [ "$(echo $output | jq -r '.actions[0].name')" = "custom_sm_action_test" ]
}

@test "Update a subject mapping" {
    skip "Temporarily disabled [namespaced-actions]: expected action ID assertion is failing in CI"
    run ./otdfctl $HOST $WITH_CREDS policy sm create -a "$SM_VAL1_ID" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_2" --json
    assert_success
    scs_to_update_with_id=$(echo "$output" | jq -r '.subject_condition_set.id')
    assert_not_equal "$scs_to_update_with_id" "null"
    assert_not_equal "$scs_to_update_with_id" ""

    run ./otdfctl $HOST $WITH_CREDS policy sm create -a "$SM_VAL1_ID" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json
    assert_success
    created=$(echo "$output" | jq -r '.id')
    assert_not_equal "$created" "null"
    assert_not_equal "$created" ""

    # replace the action (always destructive replacement)
    run_otdfctl_sm update --id "$created" --action "$ACTION_CREATE_NAME" --json
        assert_success
        [ "$(echo $output | jq -r '.id')" = "$created" ]
        [ "$(echo $output | jq -r '.actions[0].name')" = "$ACTION_CREATE_NAME" ]
        [ "$(echo $output | jq -r '.actions[0].id')" = "$ACTION_CREATE_ID" ]

    # reassign the SCS being mapped to
    run_otdfctl_sm update --id "$created" --subject-condition-set-id "$scs_to_update_with_id" --json
    assert_success
    assert_equal "$(echo $output | jq -r '.id')" "$created"
    assert_equal "$(echo $output | jq -r '.subject_condition_set.id')" "$scs_to_update_with_id"
}

@test "List subject mappings" {
    created=$(./otdfctl $HOST $WITH_CREDS policy sm create -a "$SM_VAL1_ID" --action "$ACTION_CREATE_NAME" --subject-condition-set-new "$SCS_2" --json | jq -r '.id')

    run_otdfctl_sm list
        assert_success
        assert_output --partial "$created"
        assert_output --partial "Namespace"
        assert_output --partial "Total"
        assert_line --regexp "Current Offset.*0"

    run_otdfctl_sm list --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg id "$created" '.subject_mappings[] | select(.id == $id) | .attribute_value.fqn')" "$NS_FQN/attr/attr1/value/val1"
    assert_not_equal $(echo "$output" | jq -r 'pagination') "null"
    total=$(echo "$output" | jq -r '.pagination.total')
    [[ "$total" -ge 1 ]]
}

@test "List subject mappings supports sort and order flags" {
    sort_attr=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name "sort_sm_${BATS_TEST_NUMBER}_$RANDOM" --rule ANY_OF -v "sort_sm_a" -v "sort_sm_b" -v "sort_sm_c" --json)
    sort_val_a_id=$(echo "$sort_attr" | jq -r '.values[0].id')
    sort_val_b_id=$(echo "$sort_attr" | jq -r '.values[1].id')
    sort_val_c_id=$(echo "$sort_attr" | jq -r '.values[2].id')
    sm_a_id=$(./otdfctl $HOST $WITH_CREDS policy sm create --namespace "$NS_ID" -a "$sort_val_a_id" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json | jq -r '.id')
    sm_b_id=$(./otdfctl $HOST $WITH_CREDS policy sm create --namespace "$NS_ID" -a "$sort_val_b_id" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json | jq -r '.id')
    sm_c_id=$(./otdfctl $HOST $WITH_CREDS policy sm create --namespace "$NS_ID" -a "$sort_val_c_id" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json | jq -r '.id')

    run_otdfctl_sm list --namespace "$NS_ID" --sort created_at --order asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$sm_a_id" --arg b "$sm_b_id" --arg c "$sm_c_id" '[.subject_mappings[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$sm_a_id,$sm_b_id,$sm_c_id"

    run_otdfctl_sm list --namespace "$NS_ID" --sort created_at --order desc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$sm_a_id" --arg b "$sm_b_id" --arg c "$sm_c_id" '[.subject_mappings[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$sm_c_id,$sm_b_id,$sm_a_id"

    run_otdfctl_sm update --id "$sm_a_id" --label sort=a --json
    assert_success
    run_otdfctl_sm update --id "$sm_b_id" --label sort=b --json
    assert_success
    run_otdfctl_sm update --id "$sm_c_id" --label sort=c --json
    assert_success

    run_otdfctl_sm list --namespace "$NS_ID" --sort updated_at --order asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$sm_a_id" --arg b "$sm_b_id" --arg c "$sm_c_id" '[.subject_mappings[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$sm_a_id,$sm_b_id,$sm_c_id"

    run_otdfctl_sm list --namespace "$NS_ID" --sort created_at --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$sm_a_id" --arg b "$sm_b_id" --arg c "$sm_c_id" '[.subject_mappings[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$sm_c_id,$sm_b_id,$sm_a_id"

    run_otdfctl_sm list --namespace "$NS_ID" --order asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$sm_a_id" --arg b "$sm_b_id" --arg c "$sm_c_id" '[.subject_mappings[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$sm_a_id,$sm_b_id,$sm_c_id"

    run_otdfctl_sm delete --id "$sm_a_id" --force
    run_otdfctl_sm delete --id "$sm_b_id" --force
    run_otdfctl_sm delete --id "$sm_c_id" --force
}

@test "Create subject mapping with namespace ID" {
    run ./otdfctl $HOST $WITH_CREDS policy subject-mappings create -a "$SM_VAL2_ID" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_2" --namespace "$NS_ID" --json
    assert_success
    assert_equal "$(echo "$output" | jq -r '.namespace.id')" "$NS_ID"
    assert_equal "$(echo "$output" | jq -r '.attribute_value.id')" "$SM_VAL2_ID"
    assert_not_equal "$(echo "$output" | jq -r '.subject_condition_set.id')" "null"
    assert_equal "$(echo "$output" | jq -r '.. | .subject_external_selector_value? // empty' | head -n 1)" ".team.name"
    created=$(echo "$output" | jq -r '.id')
    run_otdfctl_sm delete --id "$created" --force
    assert_success
}

@test "Create subject mapping with namespace FQN" {
    run ./otdfctl $HOST $WITH_CREDS policy subject-mappings create -a "$SM_VAL2_ID" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_2" --namespace "$NS_FQN" --json
    assert_success
    assert_equal "$(echo "$output" | jq -r '.namespace.id')" "$NS_ID"
    assert_equal "$(echo "$output" | jq -r '.attribute_value.id')" "$SM_VAL2_ID"
    assert_not_equal "$(echo "$output" | jq -r '.subject_condition_set.id')" "null"
    assert_output --partial ".team.name"
    created=$(echo "$output" | jq -r '.id')

    run_otdfctl_sm delete --id "$created" --force
    assert_success
}

@test "List subject mappings with namespace" {
    test_ns_name="subject-mappings-list-$BATS_TEST_NUMBER.net"
    test_ns_fqn="https://$test_ns_name"
    test_ns_id=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$test_ns_name" --json | jq -r '.id')
    test_attr_id=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$test_ns_id" --name attr-list --rule ANY_OF --json | jq -r '.id')
    test_val_id=$(./otdfctl $HOST $WITH_CREDS policy attributes values create --attribute-id "$test_attr_id" --value val-list --json | jq -r '.id')
    created=$(./otdfctl $HOST $WITH_CREDS policy sm create -a "$test_val_id" --action "$ACTION_CREATE_NAME" --subject-condition-set-new "$SCS_2" --namespace "$test_ns_id" --json | jq -r '.id')

    run_otdfctl_sm list --namespace "$test_ns_id"
        assert_success
        assert_output --partial "$created"
        assert_output --partial "Total"

    run_otdfctl_sm list --namespace "$test_ns_id" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg id "$created" '.subject_mappings[] | select(.id == $id) | .id')" "$created"
        # Ensure only subject mappings from the filtered namespace are returned
        assert_equal "$(echo "$output" | jq -r --arg ns "$test_ns_id" '[.subject_mappings[] | select(.namespace.id != $ns)] | length')" "0"

    # Filter by namespace fqn
    run_otdfctl_sm list --namespace "$test_ns_fqn" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg id "$created" '.subject_mappings[] | select(.id == $id) | .id')" "$created"
        # Ensure only subject mappings from the filtered namespace are returned
        assert_equal "$(echo "$output" | jq -r --arg ns "$test_ns_id" '[.subject_mappings[] | select(.namespace.id != $ns)] | length')" "0"

    ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --force --id "$test_ns_id"
}

@test "Delete subject mapping" {
    # Create a subject mapping specifically for deletion to avoid race conditions in parallel test execution
    to_delete=$(./otdfctl $HOST $WITH_CREDS policy sm create -a "$SM_VAL1_ID" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json | jq -r '.id')
    # --force to avoid indefinite hang waiting for confirmation
    run_otdfctl_sm delete --id "$to_delete" --force
        assert_success
        assert_line --regexp "Id.*$to_delete"
}
