#!/usr/bin/env bats

# Tests for dynamic value mappings

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'

    export NS_NAME="dynamic-value-mappings-test.net"
    export NS_FQN="https://$NS_NAME"
    export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$NS_NAME" --json | jq -r '.id')

    # A non-hierarchy definition used by the happy-path tests
    ATTR=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name attr1 --rule ANY_OF --json)
    export DVM_ATTR_ID=$(echo "$ATTR" | jq -r '.id')
    export DVM_ATTR_FQN=$(echo "$ATTR" | jq -r '.fqn')

    # A HIERARCHY definition, unsupported by dynamic value mappings
    export DVM_HIER_ATTR_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name hierattr --rule HIERARCHY -v high -v low --json | jq -r '.id')

    export SELECTOR='.patientAssignments[]'
    export SCS_1='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["clinician"],"subject_external_selector_value":".role"}],"boolean_operator":1}]}]'

    export ACTION_READ_NAME='read'
    export ACTION_CREATE_NAME='create'
}

setup() {
    bats_load_library bats-support
    bats_load_library bats-assert

    # invoke binary with credentials
    run_otdfctl_dvm () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings $*"
    }
}

teardown_file() {
    # remove the created namespace with all underneath upon test suite completion
    ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --force --id "$NS_ID"

    unset HOST WITH_CREDS NS_ID NS_FQN NS_NAME DVM_ATTR_ID DVM_ATTR_FQN DVM_HIER_ATTR_ID SELECTOR SCS_1
}

@test "Create dynamic value mapping" {
    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME"
        assert_success
        assert_output --partial "Attribute Definition: Id"
        assert_output --partial "Resolver: Selector"
        assert_line --regexp "Resolver: Operator.*IN"
        assert_line --regexp "Attribute Definition: Id.*$DVM_ATTR_ID"

    # json shape
    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN_CONTAINS --action "$ACTION_READ_NAME" --json
        assert_success
        [ "$(echo "$output" | jq -r '.attribute_definition.id')" = "$DVM_ATTR_ID" ]
        [ "$(echo "$output" | jq -r '.value_resolver.subject_external_selector_value')" = "$SELECTOR" ]
        # IN_CONTAINS enum serializes as 3
        [ "$(echo "$output" | jq -r '.value_resolver.operator')" = "3" ]
        [ "$(echo "$output" | jq -r '.actions[0].name')" = "$ACTION_READ_NAME" ]
}

@test "Create dynamic value mapping with a static pre-gate subject condition set" {
    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json
        assert_success
        assert_not_equal "$(echo "$output" | jq -r '.subject_condition_set.id')" "null"
        assert_not_equal "$(echo "$output" | jq -r '.subject_condition_set.id')" ""
        assert_output --partial ".role"
}

@test "Create dynamic value mapping by attribute definition FQN" {
    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings create --attribute-definition-fqn "$DVM_ATTR_FQN" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r '.attribute_definition.fqn')" "$DVM_ATTR_FQN"
}

@test "Create dynamic value mapping with namespace ID and FQN" {
    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --namespace "$NS_ID" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r '.namespace.id')" "$NS_ID"

    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mappings create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --namespace "$NS_FQN" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r '.namespace.id')" "$NS_ID"
}

@test "Create dynamic value mapping rejects invalid input" {
    # NOT_IN operator is rejected client-side
    run_otdfctl_dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator NOT_IN --action "$ACTION_READ_NAME"
        assert_failure
        assert_output --partial "Invalid --operator"

    # operator is required
    run_otdfctl_dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --action "$ACTION_READ_NAME"
        assert_failure
        assert_output --partial "resolver operator [--operator] is required"

    # an attribute definition reference is required
    run_otdfctl_dvm create --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME"
        assert_failure
        assert_output --partial "[--attribute-definition-id, --attribute-definition-fqn] is required"

    # an action is required
    run_otdfctl_dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN
        assert_failure
        assert_output --partial "At least one Action [--action] is required"
}

@test "Create dynamic value mapping rejects a HIERARCHY definition" {
    run_otdfctl_dvm create --attribute-definition-id "$DVM_HIER_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME"
        assert_failure
}

@test "Create dynamic value mapping rejects coexistence with value subject mappings" {
    run ./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name "coex_${BATS_TEST_NUMBER}_$RANDOM" --rule ANY_OF -v v1 --json
    assert_success
    coex_attr_id=$(echo "$output" | jq -r '.id')
    coex_val_id=$(echo "$output" | jq -r '.values[0].id')
    assert_not_equal "$coex_attr_id" ""
    assert_not_equal "$coex_val_id" ""

    # attach a value-level subject mapping to the definition
    run ./otdfctl $HOST $WITH_CREDS policy subject-mappings create -a "$coex_val_id" --action "$ACTION_READ_NAME" --subject-condition-set-new "$SCS_1" --json
    assert_success

    # a dynamic value mapping on the same definition must be rejected by the server
    run_otdfctl_dvm create --attribute-definition-id "$coex_attr_id" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME"
        assert_failure
}

@test "Get dynamic value mapping" {
    # exercise the singular 'dynamic-value-mapping' alias here
    run ./otdfctl $HOST $WITH_CREDS policy dynamic-value-mapping create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --json
        assert_success
        created=$(echo "$output" | jq -r '.id')
        assert_not_equal "$created" "null"
        assert_not_equal "$created" ""

    # table
    run_otdfctl_dvm get --id "$created"
        assert_success
        assert_line --regexp "Id.*$created"
        assert_line --regexp "Attribute Definition: Id.*$DVM_ATTR_ID"
        assert_line --regexp "Resolver: Operator.*IN"

    # json
    run_otdfctl_dvm get --id "$created" --json
        assert_success
        [ "$(echo "$output" | jq -r '.id')" = "$created" ]
        [ "$(echo "$output" | jq -r '.value_resolver.subject_external_selector_value')" = "$SELECTOR" ]
}

@test "List dynamic value mappings" {
    created=$(./otdfctl $HOST $WITH_CREDS policy dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --json | jq -r '.id')

    run_otdfctl_dvm list
        assert_success
        assert_output --partial "$created"
        assert_output --partial "Total"
        assert_line --regexp "Current Offset.*0"

    run_otdfctl_dvm list --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg id "$created" '.dynamic_value_mappings[] | select(.id == $id) | .id')" "$created"
        total=$(echo "$output" | jq -r '.pagination.total')
        [[ "$total" -ge 1 ]]

    # filter by attribute definition id
    run_otdfctl_dvm list --attribute-definition-id "$DVM_ATTR_ID" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg id "$DVM_ATTR_ID" '[.dynamic_value_mappings[] | select(.attribute_definition.id != $id)] | length')" "0"
}

@test "List dynamic value mappings supports namespace filter" {
    created=$(./otdfctl $HOST $WITH_CREDS policy dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --namespace "$NS_ID" --json | jq -r '.id')

    run_otdfctl_dvm list --namespace "$NS_ID" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg id "$created" '.dynamic_value_mappings[] | select(.id == $id) | .id')" "$created"
        assert_equal "$(echo "$output" | jq -r --arg ns "$NS_ID" '[.dynamic_value_mappings[] | select(.namespace.id != $ns)] | length')" "0"

    run_otdfctl_dvm list --namespace "$NS_FQN" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg id "$created" '.dynamic_value_mappings[] | select(.id == $id) | .id')" "$created"
}

@test "List dynamic value mappings supports sort and order flags" {
    sort_attr=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name "sort_dvm_${BATS_TEST_NUMBER}_$RANDOM" --rule ANY_OF --json | jq -r '.id')
    dvm_a=$(./otdfctl $HOST $WITH_CREDS policy dvm create --attribute-definition-id "$sort_attr" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --namespace "$NS_ID" --json | jq -r '.id')
    dvm_b=$(./otdfctl $HOST $WITH_CREDS policy dvm create --attribute-definition-id "$sort_attr" --selector "$SELECTOR" --operator IN --action "$ACTION_CREATE_NAME" --namespace "$NS_ID" --json | jq -r '.id')

    run_otdfctl_dvm list --namespace "$NS_ID" --sort created_at --order asc --limit 500 --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg a "$dvm_a" --arg b "$dvm_b" '[.dynamic_value_mappings[] | select(.id == $a or .id == $b) | .id] | join(",")')" "$dvm_a,$dvm_b"

    run_otdfctl_dvm list --namespace "$NS_ID" --sort created_at --order desc --limit 500 --json
        assert_success
        assert_equal "$(echo "$output" | jq -r --arg a "$dvm_a" --arg b "$dvm_b" '[.dynamic_value_mappings[] | select(.id == $a or .id == $b) | .id] | join(",")')" "$dvm_b,$dvm_a"
}

@test "Update a dynamic value mapping" {
    created=$(./otdfctl $HOST $WITH_CREDS policy dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --json | jq -r '.id')

    # replace the actions
    run_otdfctl_dvm update --id "$created" --action "$ACTION_CREATE_NAME" --json
        assert_success
        assert_equal "$(echo "$output" | jq -r '.id')" "$created"

    run_otdfctl_dvm get --id "$created" --json
        assert_success
        [ "$(echo "$output" | jq -r '.actions[0].name')" = "$ACTION_CREATE_NAME" ]

    # replace the resolver (selector + operator together)
    run_otdfctl_dvm update --id "$created" --selector ".newSelector[]" --operator IN_CONTAINS --json
        assert_success

    run_otdfctl_dvm get --id "$created" --json
        assert_success
        [ "$(echo "$output" | jq -r '.value_resolver.subject_external_selector_value')" = ".newSelector[]" ]
        [ "$(echo "$output" | jq -r '.value_resolver.operator')" = "3" ]

    # selector and operator must be provided together
    run_otdfctl_dvm update --id "$created" --selector ".onlySelector[]"
        assert_failure
        assert_output --partial "Both [--selector, --operator] must be provided together"
}

@test "Delete dynamic value mapping" {
    to_delete=$(./otdfctl $HOST $WITH_CREDS policy dvm create --attribute-definition-id "$DVM_ATTR_ID" --selector "$SELECTOR" --operator IN --action "$ACTION_READ_NAME" --json | jq -r '.id')

    run_otdfctl_dvm delete --id "$to_delete" --force
        assert_success
        assert_line --regexp "Id.*$to_delete"

    # deletion must persist
    run_otdfctl_dvm get --id "$to_delete"
        assert_failure
}
