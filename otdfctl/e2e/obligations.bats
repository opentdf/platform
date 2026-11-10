#!/usr/bin/env bats

# Tests for obligations

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'

    # create attribute value to be used in obligation values tests
    export NS_NAME="test-obl.org"
    export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name "$NS_NAME" --json | jq -r '.id')
   
    # create obligation used in obligation values tests
    export OBL_NAME="test_obl_for_values"
    export OBL_ID=$(./otdfctl $HOST $WITH_CREDS policy obligations create --name "$OBL_NAME" --namespace "$NS_ID" --json | jq -r '.id')
    
    # shared triggers file for tests
    export SHARED_TRIGGERS_FILE="/tmp/shared_test_triggers.json"
    
    # create shared actions for tests
    export ACTION_1_NAME="test_action_1"
    export ACTION_1_ID=$(./otdfctl $HOST $WITH_CREDS policy actions create --name "$ACTION_1_NAME" --json | jq -r '.id')
    export ACTION_2_NAME="test_action_2"
    export ACTION_2_ID=$(./otdfctl $HOST $WITH_CREDS policy actions create --name "$ACTION_2_NAME" --json | jq -r '.id')
    
    # create shared attributes for tests
    export ATTR_NAME="test_attr_for_triggers"
    export ATTR_VAL_NAME="test_val_for_triggers"
    attr_result=$(./otdfctl $HOST $WITH_CREDS policy attributes create --name "$ATTR_NAME" --namespace "$NS_ID" --rule "HIERARCHY" -v "$ATTR_VAL_NAME" --json)
    export ATTR_ID=$(echo "$attr_result" | jq -r '.id')
    export ATTR_VAL_ID=$(echo "$attr_result" | jq -r '.values[0].id')
    export ATTR_VAL_FQN=$(echo "$attr_result" | jq -r '.values[0].fqn')
    
    export ATTR_2_NAME="test_attr_for_triggers_2"
    export ATTR_2_VAL_NAME="test_val_for_triggers_2"
    attr_2_result=$(./otdfctl $HOST $WITH_CREDS policy attributes create --name "$ATTR_2_NAME" --namespace "$NS_ID" --rule "HIERARCHY" -v "$ATTR_2_VAL_NAME" --json)
    export ATTR_2_ID=$(echo "$attr_2_result" | jq -r '.id')
    export ATTR_2_VAL_ID=$(echo "$attr_2_result" | jq -r '.values[0].id')
    export ATTR_2_VAL_FQN=$(echo "$attr_2_result" | jq -r '.values[0].fqn')

    # Create namespaces and attributes for list triggers tests
    export LIST_NS_1_NAME="list-test-ns1.org"
    export LIST_NS_1_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name "$LIST_NS_1_NAME" --json | jq -r '.id')
    export LIST_NS_1_FQN="https://$LIST_NS_1_NAME"
    
    export LIST_NS_2_NAME="list-test-ns2.org"
    export LIST_NS_2_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name "$LIST_NS_2_NAME" --json | jq -r '.id')
    export LIST_NS_2_FQN="https://$LIST_NS_2_NAME"
    
    # Create attributes for list triggers tests
    # Namespace 1 attributes
    list_attr_1_result=$(./otdfctl $HOST $WITH_CREDS policy attributes create --name "list_test_attr" --namespace "$LIST_NS_1_ID" --rule "HIERARCHY" -v "val1" --json)
    export LIST_ATTR_1_ID=$(echo "$list_attr_1_result" | jq -r '.id')
    export LIST_ATTR_1_VAL_1_ID=$(echo "$list_attr_1_result" | jq -r '.values[0].id')
    export LIST_ATTR_1_VAL_1_FQN=$(echo "$list_attr_1_result" | jq -r '.values[0].fqn')
    
    # Namespace 2 attributes
    list_attr_2_result=$(./otdfctl $HOST $WITH_CREDS policy attributes create --name "list_test_attr" --namespace "$LIST_NS_2_ID" --rule "HIERARCHY" -v "val1" --json)
    export LIST_ATTR_2_ID=$(echo "$list_attr_2_result" | jq -r '.id')
    export LIST_ATTR_2_VAL_1_ID=$(echo "$list_attr_2_result" | jq -r '.values[0].id')
    export LIST_ATTR_2_VAL_1_FQN=$(echo "$list_attr_2_result" | jq -r '.values[0].fqn')
    
    # Set global vars for list triggers tests that will get populated in setup_triggers_test_data
    export CLIENT_ID_LIST="test-client-list"
}

setup() {
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"

    # invoke binary with credentials
    run_otdfctl_obl () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations $*"
    }
    run_otdfctl_obl_values () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations values $*"
    }
    run_otdfctl_obl_triggers () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations triggers $*"
    }

    run_otdfctl_action () {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy actions $*"
    }

    run_otdfctl_attr() {
      run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes $*"
    }

    # Cleanup helper functions
    cleanup_obligation_value() {
      local value_id="$1"
      if [ -n "$value_id" ] && [ "$value_id" != "null" ]; then
        run_otdfctl_obl_values delete --id "$value_id" --force
      fi
    }

    cleanup_action() {
      local action_id="$1"
      if [ -n "$action_id" ] && [ "$action_id" != "null" ]; then
        run_otdfctl_action delete --id "$action_id" --force
      fi
    }

    cleanup_attribute() {
      local attr_id="$1"
      if [ -n "$attr_id" ] && [ "$attr_id" != "null" ]; then
        run_otdfctl_attr unsafe delete --id "$attr_id" --force
      fi
    }

    cleanup_trigger() {
      local trigger_id="$1"
      if [ -n "$trigger_id" ] && [ "$trigger_id" != "null" ]; then
        run_otdfctl_obl_triggers delete --id "$trigger_id" --force
      fi
    }

    cleanup_temp_file() {
      local file_path="$1"
      if [ -n "$file_path" ] && [ -f "$file_path" ]; then
        rm -f "$file_path"
      fi
    }

    # Validate triggers in JSON response
    validate_triggers() {
      local json_output="$1"
      local expected_count="$2"
      shift 2
      local expected_triggers=("$@")  # Array of expected trigger specs: "attr_val_id;attr_val_fqn;action_id;action_name;client_id"
      
      # Validate trigger count
      local actual_count=$(echo "$json_output" | jq -r '.triggers | length')
      assert_equal "$actual_count" "$expected_count"
      
      # Validate each expected trigger exists in the response
      for expected_trigger in "${expected_triggers[@]}"; do
        IFS=';' read -ra TRIGGER_SPEC <<< "$expected_trigger"
        local exp_attr_val_id="${TRIGGER_SPEC[0]}"
        local exp_attr_val_fqn="${TRIGGER_SPEC[1]}"
        local exp_action_id="${TRIGGER_SPEC[2]}"
        local exp_action_name="${TRIGGER_SPEC[3]}"
        local exp_client_id="${TRIGGER_SPEC[4]}"
        local exp_obl_val_id="${TRIGGER_SPEC[5]}"
        local exp_obl_val_fqn="${TRIGGER_SPEC[6]}"
        
        # Find if this expected trigger exists in the response
        local found=false
        for ((i=0; i<expected_count; i++)); do
          local match=true
          
          # Check attribute value ID if specified
          if [[ -n "$exp_attr_val_id" && "$exp_attr_val_id" != "null" ]]; then
            local actual_attr_val_id=$(echo "$json_output" | jq -r ".triggers[$i].attribute_value.id")
            if [ "$actual_attr_val_id" != "$exp_attr_val_id" ]; then
              match=false
            fi
          fi
          
          # Check attribute value FQN if specified
          if [ "$match" = true ] && [ -n "$exp_attr_val_fqn" ] && [ "$exp_attr_val_fqn" != "null" ]; then
            local actual_attr_val_fqn=$(echo "$json_output" | jq -r ".triggers[$i].attribute_value.fqn")
            if [ "$actual_attr_val_fqn" != "$exp_attr_val_fqn" ]; then
              match=false
            fi
          fi
          
          # Check action ID if specified
          if [ "$match" = true ] && [ -n "$exp_action_id" ] && [ "$exp_action_id" != "null" ]; then
            local actual_action_id=$(echo "$json_output" | jq -r ".triggers[$i].action.id")
            if [ "$actual_action_id" != "$exp_action_id" ]; then
              match=false
            fi
          fi
          
          # Check action name if specified
          if [ "$match" = true ] && [ -n "$exp_action_name" ] && [ "$exp_action_name" != "null" ]; then
            local actual_action_name=$(echo "$json_output" | jq -r ".triggers[$i].action.name")
            if [ "$actual_action_name" != "$exp_action_name" ]; then
              match=false
            fi
          fi
          
          # Check client_id if specified
          if [ "$match" = true ] && [ -n "$exp_client_id" ] && [ "$exp_client_id" != "null" ]; then
            local actual_client_id=$(echo "$json_output" | jq -r "if .triggers[$i].context and (.triggers[$i].context | length) > 0 then .triggers[$i].context[0].pep.client_id // \"\" else \"\" end")
            if [ "$actual_client_id" != "$exp_client_id" ]; then
              match=false
            fi
          fi

          # Check obligation value ID if specified
          if [ "$match" = true ] && [ -n "$exp_obl_val_id" ] && [ "$exp_obl_val_id" != "null" ]; then
            local actual_obl_val_id=$(echo "$json_output" | jq -r ".triggers[$i].obligation_value.id")
            if [ "$actual_obl_val_id" != "$exp_obl_val_id" ]; then
              match=false
            fi
          fi

          # Check obligation value FQN if specified
          if [ "$match" = true ] && [ -n "$exp_obl_val_fqn" ] && [ "$exp_obl_val_fqn" != "null" ]; then
            local actual_obl_val_fqn=$(echo "$json_output" | jq -r ".triggers[$i].obligation_value.fqn")
            if [ "$actual_obl_val_fqn" != "$exp_obl_val_fqn" ]; then
              match=false
            fi
          fi
          
          if [ "$match" = true ]; then
            found=true
            break
          fi
        done
        
        # Assert that we found this expected trigger
        if [ "$found" = false ]; then
          echo "Expected trigger not found: attr_val_id=$exp_attr_val_id, attr_val_fqn=$exp_attr_val_fqn, action_id=$exp_action_id, action_name=$exp_action_name, client_id=$exp_client_id, obl_val_id=$exp_obl_val_id, obl_val_fqn=$exp_obl_val_fqn"
          return 1
        fi
      done
    }

    setup_triggers_test_data() {
      export LIST_OBL_1_NAME="list_test_obl"
      export LIST_OBL_1_VAL="list_test_val"
      export LIST_OBL_1_FQN="https://$LIST_NS_1_NAME/obl/$LIST_OBL_1_NAME"
      export LIST_OBL_VAL_1_FQN="$LIST_OBL_1_FQN/value/$LIST_OBL_1_VAL"
      export LIST_OBL_1_ID=""
      export LIST_OBL_2_NAME="list_test_obl"
      export LIST_OBL_2_VAL="list_test_val"
      export LIST_OBL_2_FQN="https://$LIST_NS_2_NAME/obl/$LIST_OBL_2_NAME"
      export LIST_OBL_VAL_2_FQN="$LIST_OBL_2_FQN/value/$LIST_OBL_2_VAL"
      export LIST_OBL_2_ID=""

      run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations get --fqn $LIST_OBL_1_FQN --json"
      if [ $status -ne 0 ]; then
        run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations create --name "$LIST_OBL_1_NAME" --namespace "$LIST_NS_1_ID" --json"
        assert_success
        export LIST_OBL_1_ID=$(echo "$output" | jq -r '.id')

        run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$LIST_OBL_1_ID" --value "$LIST_OBL_1_VAL" --json"
        assert_success
        export LIST_OBL_VAL_1_ID=$(echo "$output" | jq -r '.id')

        run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations triggers create --attribute-value "$LIST_ATTR_1_VAL_1_ID" --action "$ACTION_1_ID" --obligation-value "$LIST_OBL_VAL_1_ID" --client-id "$CLIENT_ID_LIST" --json"
        assert_success
        export LIST_TRIGGER_1_ID=$(echo "$output" | jq -r '.id')
      else
        export LIST_OBL_1_ID=$(echo "$output" | jq -r '.id')
        export LIST_OBL_VAL_1_ID=$(echo "$output" | jq -r '.values[0].id')
        export LIST_TRIGGER_1_ID=$(echo "$output" | jq -r '.values[0].triggers[0].id')
      fi

      run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations get --fqn $LIST_OBL_2_FQN --json"
      if [ $status -ne 0 ]; then
        run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations create --name "$LIST_OBL_2_NAME" --namespace "$LIST_NS_2_ID" --json"
        assert_success
        export LIST_OBL_2_ID=$(echo "$output" | jq -r '.id')

        run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$LIST_OBL_2_ID" --value "$LIST_OBL_2_VAL" --json"
        assert_success
        export LIST_OBL_VAL_2_ID=$(echo "$output" | jq -r '.id')

        run sh -c "./otdfctl $HOST $WITH_CREDS policy obligations triggers create --attribute-value "$LIST_ATTR_2_VAL_1_ID" --action "$ACTION_2_ID" --obligation-value "$LIST_OBL_VAL_2_ID" --client-id "$CLIENT_ID_LIST" --json"
        assert_success
        export LIST_TRIGGER_2_ID=$(echo "$output" | jq -r '.id')
      else
        export LIST_OBL_2_ID=$(echo "$output" | jq -r '.id')
        export LIST_OBL_VAL_2_ID=$(echo "$output" | jq -r '.values[0].id')
        export LIST_TRIGGER_2_ID=$(echo "$output" | jq -r '.values[0].triggers[0].id')
      fi
  }

  validate_pagination() {
    local json_output="$1"
    local expected_offset="$2"
    local expected_total="$3"
    local expected_next_offset="$4"
    assert_equal "$(echo "$json_output" | jq -r '.pagination.current_offset')" "$expected_offset"
    assert_equal "$(echo "$json_output" | jq -r '.pagination.total')" "$expected_total"
    assert_equal "$(echo "$json_output" | jq -r '.pagination.next_offset')" "$expected_next_offset"
  }
}

teardown_file() {
  # remove the obligation used in obligation values tests
  ./otdfctl $HOST $WITH_CREDS policy obligations delete --id "$OBL_ID" --force

  # remove shared actions
  ./otdfctl $HOST $WITH_CREDS policy actions delete --id "$ACTION_1_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy actions delete --id "$ACTION_2_ID" --force
  
  # remove shared attributes
  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --id "$ATTR_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --id "$ATTR_2_ID" --force

  # remove the namespace used in obligation values tests
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_ID" --force
  
  # remove list triggers test namespaces
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$LIST_NS_1_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$LIST_NS_2_ID" --force
  
  # cleanup shared triggers file
  rm -f "$SHARED_TRIGGERS_FILE"

  # clear out all test env vars
  unset HOST WITH_CREDS OBL_NAME OBL_ID NS_NAME NS_ID ACTION_1_NAME ACTION_1_ID ACTION_2_NAME ACTION_2_ID ATTR_NAME ATTR_VAL_NAME ATTR_ID ATTR_VAL_ID ATTR_VAL_FQN ATTR_2_NAME ATTR_2_VAL_NAME ATTR_2_ID ATTR_2_VAL_ID ATTR_2_VAL_FQN
  unset CLIENT_ID_LIST LIST_NS_1_NAME LIST_NS_1_ID LIST_NS_1_FQN LIST_NS_2_NAME LIST_NS_2_ID LIST_NS_2_FQN
  unset LIST_ATTR_1_ID LIST_ATTR_1_VAL_1_ID LIST_ATTR_1_VAL_1_FQN LIST_ATTR_2_ID LIST_ATTR_2_VAL_1_ID LIST_ATTR_2_VAL_1_FQN
}


@test "Create a obligation - Good" {
  run_otdfctl_obl create --name test_create_obl --namespace "$NS_ID" --json
    assert_success
    [ "$(echo "$output" | jq -r '.name')" = "test_create_obl" ]
    [ -n "$(echo "$output" | jq -r '.id')" ]
    [ -n "$(echo "$output" | jq -r '.created_at')" ]
    [ -n "$(echo "$output" | jq -r '.updated_at')" ]

  # cleanup
  created_id="$(echo "$output" | jq -r '.id')"
  run_otdfctl_obl delete --id "$created_id" --force
}

@test "Create a obligation - Bad" {
  # bad obligation names
  run_otdfctl_obl create --name ends_underscored_ --namespace "$NS_ID"
    assert_failure
  run_otdfctl_obl create --name -first-char-hyphen --namespace "$NS_ID"
    assert_failure
  run_otdfctl_obl create --name inval!d.chars --namespace "$NS_ID"
    assert_failure

  # missing flag
  run_otdfctl_obl create
    assert_failure
    assert_output --partial "Flag '--name' is required"
  
  # conflict
  run_otdfctl_obl create --name test_create_obl_conflict --namespace "$NS_ID" --json
    assert_success
  created_id="$(echo "$output" | jq -r '.id')"
  run_otdfctl_obl create --name test_create_obl_conflict --namespace "$NS_ID"
      assert_failure
      assert_output --partial "already_exists"

  # cleanup
  run_otdfctl_obl delete --id $created_id --force
}

@test "Get an obligation - Good" {
  # setup an obligation to get
  run_otdfctl_obl create --name test_get_obl --namespace "$NS_ID" --json
    assert_success
  created_id="$(echo "$output" | jq -r '.id')"

  # get by id
  run_otdfctl_obl get --id "$created_id" --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.name')" = "test_get_obl" ]

  # get by fqn
  run_otdfctl_obl get --fqn "https://${NS_NAME}/obl/test_get_obl" --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.name')" = "test_get_obl" ]

  # cleanup
  run_otdfctl_obl delete --id $created_id --force
}

@test "Get an obligation - Bad" {
  run_otdfctl_obl get
    assert_failure
    assert_output --partial "one of id, fqn must be set [message.oneof]"

  run_otdfctl_obl get --id 'not_a_uuid'
    assert_failure
    assert_output --partial "must be a valid UUID"
}

@test "List obligations" {
  # setup obligations to list
  run_otdfctl_obl create --name test_list_obl_1 --namespace "$NS_ID" --json
  obl1_id="$(echo "$output" | jq -r '.id')"
  run_otdfctl_obl create --name test_list_obl_2 --namespace "$NS_ID" --json
  obl2_id="$(echo "$output" | jq -r '.id')"

  run_otdfctl_obl list
    assert_success
    assert_output --partial "$obl1_id"
    assert_output --partial "test_list_obl_1"
    assert_output --partial "$obl2_id"
    assert_output --partial "test_list_obl_2"
    assert_output --partial "Total"
    assert_line --regexp "Current Offset.*0"
  
  run_otdfctl_obl list --json
  assert_success
  assert_not_equal $(echo "$output" | jq -r 'pagination') "null"
  total=$(echo "$output" | jq -r '.pagination.total')
  [[ "$total" -ge 1 ]]

  # cleanup
  run_otdfctl_obl delete --id $obl1_id --force
  run_otdfctl_obl delete --id $obl2_id --force
}

@test "Update obligation" {
  # setup an obligation to update
  run_otdfctl_obl create --name test_update_obl --namespace "$NS_ID" --json
    assert_success
  created_id="$(echo "$output" | jq -r '.id')"

  # force replace labels
  run_otdfctl_obl update --id "$created_id" -l key=other --force-replace-labels --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.name')" = "test_update_obl" ]
    [ "$(echo "$output" | jq -r '.metadata.labels | keys | length')" = "1" ]
    [ "$(echo "$output" | jq -r '.metadata.labels.key')" = "other" ]

  # renamed
  run_otdfctl_obl update --id "$created_id" --name test_renamed_obl --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.name')" = "test_renamed_obl" ]
    [ "$(echo "$output" | jq -r '.name')" != "test_update_obl" ]

  # cleanup
  run_otdfctl_obl delete --id $created_id --force
}

@test "Delete obligation - Good" {
  # setup an obligation to delete
  run_otdfctl_obl create --name test_delete_obl --namespace "$NS_ID" --json
  created_id="$(echo "$output" | jq -r '.id')"

  run_otdfctl_obl delete --id "$created_id" --force
    assert_success
}

@test "Delete obligation - Bad" {
  # no id
  run_otdfctl_obl delete
    assert_failure
    assert_output --partial "one of id, fqn must be set [message.oneof]"

  # invalid id
  run_otdfctl_obl delete --id 'not_a_uuid'
    assert_failure
    assert_output --partial "must be a valid UUID"
}

# Tests for obligation values

@test "Create an obligation value - Good" {
  # simple by obligation ID
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_create_obl_val --json
    assert_success
    [ "$(echo "$output" | jq -r '.value')" = "test_create_obl_val" ]
    [ -n "$(echo "$output" | jq -r '.id')" ]
    [ -n "$(echo "$output" | jq -r '.created_at')" ]
    [ -n "$(echo "$output" | jq -r '.updated_at')" ]
  created_id_simple="$(echo "$output" | jq -r '.id')"

  # simple by obligation FQN
  run_otdfctl_obl_values create --obligation "https://$NS_NAME/obl/$OBL_NAME" --value test_create_obl_val_by_obl_fqn --json
    assert_success
    [ "$(echo "$output" | jq -r '.value')" = "test_create_obl_val_by_obl_fqn" ]
    [ -n "$(echo "$output" | jq -r '.id')" ]
    [ -n "$(echo "$output" | jq -r '.created_at')" ]
    [ -n "$(echo "$output" | jq -r '.updated_at')" ]
  created_id_simple_by_fqn=$(echo "$output" | jq -r '.id')
  # cleanup
  run_otdfctl_obl_values delete --id $created_id_simple --force
  run_otdfctl_obl_values delete --id $created_id_simple_by_fqn --force
}

@test "Create an obligation value - Bad" {
  # bad obligation value names
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value ends_underscored_
    assert_failure
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value -first-char-hyphen
    assert_failure
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value inval!d.chars
    assert_failure

  # missing flag
  run_otdfctl_obl_values create
    assert_failure
    assert_output --partial "Flag '--obligation' is required"
  run_otdfctl_obl_values create --obligation "$OBL_ID"
    assert_failure
    assert_output --partial "Flag '--value' is required"

  # non-existent obligation fqn
  run_otdfctl_obl_values create --obligation invalid_fqn --value test_create_obl_val
    assert_failure
    assert_output --partial "obligation_fqn: value must be a valid URI [string.uri]"
  
  # conflict
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_create_obl_val_conflict --json
    assert_success
  created_id="$(echo "$output" | jq -r '.id')"
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_create_obl_val_conflict
      assert_failure
      assert_output --partial "already_exists"

  # cleanup
  run_otdfctl_obl_values delete --id $created_id --force
}

@test "Create an obligation value with triggers - JSON Array - Success" {
  # test with single trigger (new nested format)
  triggers_json='[{"action": "'$ACTION_1_NAME'", "attribute_value": "'$ATTR_VAL_FQN'", "context": {"pep": {"client_id": "test-client"}}}]'
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_single_trigger --triggers "$triggers_json" --json
  assert_success
  single_trigger_val_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.value')" "test_val_single_trigger"
  assert_not_equal "$(echo "$output" | jq -r '.id')" "null"
  validate_triggers "$output" "1" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_1_ID;$ACTION_1_NAME;test-client"
  cleanup_obligation_value "$single_trigger_val_id"
  assert_success

  # test with multiple triggers (scoped and unscoped)
  triggers_json='[{"action": "'$ACTION_1_NAME'", "attribute_value": "'$ATTR_VAL_FQN'", "context": {"pep": {"client_id": "test-client"}}}, {"action": "'$ACTION_2_NAME'", "attribute_value": "'$ATTR_VAL_FQN'"}]'
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_multiple_triggers --triggers "$triggers_json" --json
  assert_success
  multiple_trigger_val_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.value')" "test_val_multiple_triggers"
  assert_not_equal "$(echo "$output" | jq -r '.id')" "null"
  validate_triggers "$output" "2" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_1_ID;$ACTION_1_NAME;test-client" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_2_ID;$ACTION_2_NAME;"
  cleanup_obligation_value "$multiple_trigger_val_id"
  assert_success

  # test with unscoped trigger
  triggers_json='[{"action": "'$ACTION_1_NAME'", "attribute_value": "'$ATTR_VAL_FQN'"}]'
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_unscoped_trigger --triggers "$triggers_json" --json
  assert_success
  unscoped_trigger_val_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.value')" "test_val_unscoped_trigger"
  assert_not_equal "$(echo "$output" | jq -r '.id')" "null"
  validate_triggers "$output" "1" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_1_ID;$ACTION_1_NAME;"
  cleanup_obligation_value "$unscoped_trigger_val_id"
  assert_success
}

@test "Create an obligation value with triggers - JSON File - Success" {
  # create a temporary triggers file
  cat > "$SHARED_TRIGGERS_FILE" << EOF
[
  {
    "action": "$ACTION_1_NAME",
    "attribute_value": "$ATTR_VAL_FQN",
    "context": {
      "pep": {
        "client_id": "file-client-1"
      }
    }
  },
  {
    "action": "$ACTION_2_NAME",
    "attribute_value": "$ATTR_VAL_FQN"
  }
]
EOF

  # test with triggers from file
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_val_file_triggers --triggers "$SHARED_TRIGGERS_FILE" --json
  assert_success
  file_trigger_val_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.value')" "test_val_file_triggers"
  assert_not_equal "$(echo "$output" | jq -r '.id')" "null"
  validate_triggers "$output" "2" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_1_ID;$ACTION_1_NAME;file-client-1" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_2_ID;$ACTION_2_NAME;"

  # cleanup
  cleanup_obligation_value "$file_trigger_val_id"
}

@test "Create an obligation value with triggers - Bad" {
  # test with invalid JSON
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_bad_json --triggers '{"invalid": json}'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "failed to parse trigger JSON"

  # test with missing required fields
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_missing_action --triggers '[{"attribute_value": "https://test.com/attr/test/value/test"}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "action is required"

  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_missing_attr --triggers '[{"action": "read"}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "attribute_value is required"

  # test with empty required fields
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_empty_action --triggers '[{"action": "", "attribute_value": "https://test.com/attr/test/value/test"}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "action is required"

  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_empty_attr --triggers '[{"action": "read", "attribute_value": ""}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "attribute_value is required"

  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_empty_attr --triggers '[{"attribute_value": "https://test.com/attr/test/value/test", "action": "read"}, {"action": "write"}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "attribute_value is required"

  # test with non-existent file
  run ./otdfctl $HOST $WITH_CREDS policy obligations values create --obligation "$OBL_ID" --value test_val_nonexistent_file --triggers "/nonexistent/file.json"
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "failed to parse trigger JSON"

  # test with invalid file content
  invalid_file="/tmp/invalid_triggers_$$.json"
  echo "invalid json content" > "$invalid_file"
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_val_invalid_file --triggers "$invalid_file"
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "failed to parse trigger JSON"
  rm -f "$invalid_file"
}

@test "Get an obligation value - Good" {
  # setup an obligation value to get
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_get_obl_val --json
    assert_success
  created_id=$(echo "$output" | jq -r '.id')

  # get by id
  run_otdfctl_obl_values get --id "$created_id" --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.value')" = "test_get_obl_val" ]

  # get by fqn
  run_otdfctl_obl_values get --fqn "https://$NS_NAME/obl/$OBL_NAME/value/test_get_obl_val" --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.value')" = "test_get_obl_val" ]

  # cleanup
  run_otdfctl_obl_values delete --id $created_id --force
}

@test "Get an obligation value - Bad" {
  run_otdfctl_obl_values get
    assert_failure
    assert_output --partial "one of id, fqn must be set [message.oneof]"

  # invalid id
  run_otdfctl_obl_values get --id 'not_a_uuid'
    assert_failure
    assert_output --partial "must be a valid UUID"

  # invalid fqn
  run_otdfctl_obl_values get --fqn 'not_a_fqn'
    assert_failure
    assert_output --partial "must be a valid URI"
}

@test "Update obligation values" {
  # setup an obligation value to update
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_update_obl_val --json
    assert_success
    created_id="$(echo "$output" | jq -r '.id')"

  # force replace labels
  run_otdfctl_obl_values update --id "$created_id" -l key=other --force-replace-labels --json
    assert_success
    # Check that metadata.labels has exactly one key
    [ "$(echo "$output" | jq -r '.metadata.labels | keys | length')" = "1" ]
    # Check that the key "key" exists and has value "other"
    [ "$(echo "$output" | jq -r '.metadata.labels.key')" = "other" ]

  # renamed
  run_otdfctl_obl_values update --id "$created_id" --value test_renamed_obl_val --json
    assert_success
    [ "$(echo "$output" | jq -r '.id')" = "$created_id" ]
    [ "$(echo "$output" | jq -r '.value')" = "test_renamed_obl_val" ]
    [ "$(echo "$output" | jq -r '.value')" != "test_update_obl_val" ]

  # cleanup
  run_otdfctl_obl_values delete --id $created_id --force
}

@test "Update obligation values with triggers - Success" {
  # create an obligation value to update
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_update_with_triggers --json
  assert_success
  created_id="$(echo "$output" | jq -r '.id')"

  # verify obligation value has no triggers initially
  run_otdfctl_obl_values get --id "$created_id" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "0"

  # update with triggers (new nested format)
  triggers_json='[{"action": "'$ACTION_1_NAME'", "attribute_value": "'$ATTR_2_VAL_FQN'", "context": {"pep": {"client_id": "update-client"}}}]'
  run ./otdfctl $HOST $WITH_CREDS policy obligations values update --id "$created_id" --value test_updated_with_triggers --triggers "$triggers_json" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$created_id"
  assert_equal "$(echo "$output" | jq -r '.value')" "test_updated_with_triggers"
  validate_triggers "$output" "1" "$ATTR_2_VAL_ID;$ATTR_2_VAL_FQN;$ACTION_1_ID;$ACTION_1_NAME;update-client"

  run_otdfctl_obl_values get --id "$created_id" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "1"

  # update with triggers from file
  cat > "$SHARED_TRIGGERS_FILE" << EOF
[
  {
    "action": "$ACTION_2_NAME",
    "attribute_value": "$ATTR_VAL_FQN"
  },
  {
    "action": "$ACTION_1_NAME",
    "attribute_value": "$ATTR_VAL_FQN"
  }
]
EOF

  run_otdfctl_obl_values update --id "$created_id" --value test_updated_from_file --triggers "$SHARED_TRIGGERS_FILE" --json
  assert_success
  validate_triggers "$output" "2" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_2_ID;$ACTION_2_NAME;" "$ATTR_VAL_ID;$ATTR_VAL_FQN;$ACTION_1_ID;$ACTION_1_NAME;"

  run_otdfctl_obl_values get --id "$created_id" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "2"

  # cleanup
  cleanup_obligation_value "$created_id"
}

@test "Update obligation values with triggers - Bad" {
  # create an obligation value to update
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_update_bad_triggers --json
  assert_success
  created_id="$(echo "$output" | jq -r '.id')"

  # test with invalid JSON
  run ./otdfctl $HOST $WITH_CREDS policy obligations values update --id "$created_id" --triggers '{"invalid": json}'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "failed to parse trigger JSON"

  # test with missing required fields
  run ./otdfctl $HOST $WITH_CREDS policy obligations values update --id "$created_id" --triggers '[{"attribute_value": "https://test.com/attr/test/value/test"}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "action is required"

  # Missing required fields many
  run ./otdfctl $HOST $WITH_CREDS policy obligations values update --id "$created_id" --triggers '[{"attribute_value": "https://test.com/attr/test/value/test", "action": "read"}, {"action": "write"}]'
  assert_failure
  assert_output --partial "Invalid trigger configuration"
  assert_output --partial "attribute_value is required"

  # cleanup
  cleanup_obligation_value "$created_id"
}

@test "Delete obligation value - Good" {
  # setup a value to delete
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value test_delete_obl_val --json
  created_id="$(echo "$output" | jq -r '.id')"

  run_otdfctl_obl_values delete --id "$created_id" --force
    assert_success
}

@test "Delete obligation value - Bad" {
  # no id
  run_otdfctl_obl_values delete
    assert_failure
    assert_output --partial "one of id, fqn must be set [message.oneof]"

  # invalid id
  run_otdfctl_obl_values delete --id 'not_a_uuid'
    assert_failure
    assert_output --partial "must be a valid UUID"
}

# Tests for obligation triggers

@test "Create an obligation trigger - Required Only - IDs - Success" {
  # setup an obligation value to use
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value "test_obl_val_for_trigger" --json
  obl_val_id=$(echo "$output" | jq -r '.id')

  # create trigger
  run_otdfctl_obl_triggers create --attribute-value "$ATTR_VAL_ID" --action "$ACTION_1_ID" --obligation-value "$obl_val_id" --json
  assert_success
  [ "$(echo "$output" | jq -r '.id')" != "null" ]
  trigger_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.attribute_value.id')" "$ATTR_VAL_ID"
  assert_equal "$(echo "$output" | jq -r '.attribute_value.fqn')" "$ATTR_VAL_FQN"
  assert_equal "$(echo "$output" | jq -r '.action.id')" "$ACTION_1_ID"
  assert_equal "$(echo "$output" | jq -r '.action.name')" "$ACTION_1_NAME"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.id')" "$obl_val_id"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.value')" "test_obl_val_for_trigger"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.obligation.id')" "$OBL_ID"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.obligation.namespace.fqn')" "https://$NS_NAME"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.fqn')" "https://$NS_NAME/obl/$OBL_NAME/value/test_obl_val_for_trigger"

  # cleanup
  cleanup_trigger "$trigger_id"
  cleanup_obligation_value "$obl_val_id"
}

@test "Create an obligation trigger - Required Only - FQNs - Success" {
  # setup an obligation value to use
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value "test_obl_val_for_trigger" --json
  obl_val_id=$(echo "$output" | jq -r '.id')
  obl_val_fqn="https://$NS_NAME/obl/$OBL_NAME/value/test_obl_val_for_trigger"

  # create trigger
  run_otdfctl_obl_triggers create --attribute-value "$ATTR_VAL_FQN" --action "$ACTION_1_NAME" --obligation-value "$obl_val_fqn" --json
  assert_success
  [ "$(echo "$output" | jq -r '.id')" != "null" ]
  trigger_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.attribute_value.id')" "$ATTR_VAL_ID"
  assert_equal "$(echo "$output" | jq -r '.attribute_value.fqn')" "$ATTR_VAL_FQN"
  assert_equal "$(echo "$output" | jq -r '.action.id')" "$ACTION_1_ID"
  assert_equal "$(echo "$output" | jq -r '.action.name')" "$ACTION_1_NAME"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.id')" "$obl_val_id"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.value')" "test_obl_val_for_trigger"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.obligation.id')" "$OBL_ID"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.obligation.namespace.fqn')" "https://$NS_NAME"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.fqn')" "https://$NS_NAME/obl/$OBL_NAME/value/test_obl_val_for_trigger"
  assert_equal "$(echo "$output" | jq -r '.metadata.labels')" "null"
  assert_equal "$(echo "$output" | jq -r '.context.pep')" "null"

  # cleanup
  cleanup_trigger "$trigger_id"
  cleanup_obligation_value "$obl_val_id"
}

@test "Create an obligation trigger - Optional Fields - Success" {
  # setup an obligation value to use
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value "test_obl_val_for_trigger" --json
  obl_val_id=$(echo "$output" | jq -r '.id')

  # create trigger
  client_id="a-pep"
  run_otdfctl_obl_triggers create --attribute-value "$ATTR_VAL_ID" --action "$ACTION_2_ID" --obligation-value "$obl_val_id" --client-id "$client_id" --label "my=label" --json
  assert_success
  assert_not_equal "$(echo "$output" | jq -r '.id')" "null"
  trigger_id=$(echo "$output" | jq -r '.id')
  assert_equal "$(echo "$output" | jq -r '.attribute_value.id')" "$ATTR_VAL_ID"
  assert_equal "$(echo "$output" | jq -r '.attribute_value.fqn')" "$ATTR_VAL_FQN"
  assert_equal "$(echo "$output" | jq -r '.action.id')" "$ACTION_2_ID"
  assert_equal "$(echo "$output" | jq -r '.action.name')" "$ACTION_2_NAME"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.id')" "$obl_val_id"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.value')" "test_obl_val_for_trigger"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.obligation.id')" "$OBL_ID"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.obligation.namespace.fqn')" "https://$NS_NAME"
  assert_equal "$(echo "$output" | jq -r '.metadata.labels.my')" "label"
  assert_equal "$(echo "$output" | jq -r '.context | length')" "1"
  assert_equal "$(echo "$output" | jq -r '.context[0].pep.client_id')" "$client_id"
  assert_equal "$(echo "$output" | jq -r '.obligation_value.fqn')" "https://$NS_NAME/obl/$OBL_NAME/value/test_obl_val_for_trigger"

  # cleanup
  cleanup_trigger "$trigger_id"
  cleanup_obligation_value "$obl_val_id"
}

@test "Create an obligation trigger - Bad" {
  # missing flags
  run_otdfctl_obl_triggers create --attribute-value "http://example.com/attr/attr_name/value/attr_value" --action "read" 
  assert_failure 
  assert_output --partial "Flag '--obligation-value' is required"
  
  run_otdfctl_obl_triggers create --obligation-value "http://example.com/attr/attr_name/value/attr_value" --action "read"
  assert_failure
  assert_output --partial "Flag '--attribute-value' is required"

  run_otdfctl_obl_triggers create --obligation-value "http://example.com/attr/attr_name/value/attr_value" --attribute-value "http://example.com/attr/attr_name/value/attr_value"
  assert_failure
  assert_output --partial "Flag '--action' is required"
}

@test "Delete an obligation trigger - Good" {
  # setup an obligation value to use
  run_otdfctl_obl_values create --obligation "$OBL_ID" --value "test_obl_val_for_del_trigger" --json
  assert_success
  obl_val_id=$(echo "$output" | jq -r '.id')

  # create trigger
  run_otdfctl_obl_triggers create --attribute-value "$ATTR_2_VAL_ID" --action "$ACTION_2_ID" --obligation-value "$obl_val_id" --json
  assert_success
  assert_not_equal "$(echo "$output" | jq -r '.id')" "null"
  trigger_id=$(echo "$output" | jq -r '.id')

    # delete trigger
  run_otdfctl_obl_triggers delete --id "$trigger_id" --force --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$trigger_id"

  # cleanup
  cleanup_obligation_value "$obl_val_id"
}

@test "List obligation triggers - No filters" {
  setup_triggers_test_data
  
  run_otdfctl_obl_triggers list --json
  assert_success
  
  # Verify all our triggers are present
  actual_triggers=$(echo "$output" | jq -r '.triggers | length')
  assert [ "$actual_triggers" -ge 2 ]
  validate_triggers "$output" "2" "$LIST_ATTR_2_VAL_1_ID;$LIST_ATTR_2_VAL_1_FQN;$ACTION_2_ID;$ACTION_2_NAME;$CLIENT_ID_LIST;$LIST_OBL_2_VAL_ID;$LIST_OBL_VAL_2_FQN" "$LIST_ATTR_1_VAL_1_ID;$LIST_ATTR_1_VAL_1_FQN;$ACTION_1_ID;$ACTION_1_NAME;$CLIENT_ID_LIST;$LIST_OBL_1_VAL_ID;$LIST_OBL_VAL_1_FQN"
  validate_pagination "$output" "null" "2" "null"
}

@test "List obligation triggers - Limit and Offset" {
  setup_triggers_test_data
  run_otdfctl_obl_triggers list --limit 1 --offset 0 --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "1"
  validate_triggers "$output" "1" "$LIST_ATTR_2_VAL_1_ID;$LIST_ATTR_2_VAL_1_FQN;$ACTION_2_ID;$ACTION_2_NAME;$CLIENT_ID_LIST;$LIST_OBL_2_VAL_ID;$LIST_OBL_VAL_2_FQN"
  validate_pagination "$output" "null" "2" "1"

  run_otdfctl_obl_triggers list --limit 1 --offset 1 --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "1"
  validate_triggers "$output" "1" "$LIST_ATTR_1_VAL_1_ID;$LIST_ATTR_1_VAL_1_FQN;$ACTION_1_ID;$ACTION_1_NAME;$CLIENT_ID_LIST;$LIST_OBL_1_VAL_ID;$LIST_OBL_VAL_1_FQN"
  validate_pagination "$output" "1" "2" "null"
}

@test "List obligation triggers - Filter by Namespace ID" {
  setup_triggers_test_data
  run_otdfctl_obl_triggers list --namespace "$LIST_NS_1_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "1"
  validate_triggers "$output" "1" "$LIST_ATTR_1_VAL_1_ID;$LIST_ATTR_1_VAL_1_FQN;$ACTION_1_ID;$ACTION_1_NAME;$CLIENT_ID_LIST;$LIST_OBL_1_VAL_ID;$LIST_OBL_VAL_1_FQN"
  validate_pagination "$output" "null" "1" "null"
}

@test "List obligation triggers - Filter by Namespace FQN" {
  setup_triggers_test_data
  run_otdfctl_obl_triggers list --namespace "https://$LIST_NS_2_NAME" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.triggers | length')" "1"
  validate_triggers "$output" "1" "$LIST_ATTR_2_VAL_1_ID;$LIST_ATTR_2_VAL_1_FQN;$ACTION_2_ID;$ACTION_2_NAME;$CLIENT_ID_LIST;$LIST_OBL_2_VAL_ID;$LIST_OBL_VAL_2_FQN"
  validate_pagination "$output" "null" "1" "null"
}