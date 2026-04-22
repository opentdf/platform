#!/usr/bin/env bats

load "${BATS_LIB_PATH}/bats-support/load.bash"
load "${BATS_LIB_PATH}/bats-assert/load.bash"
load "otdfctl-utils.sh"

# Tests for attributes

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  # Create the namespace to be used by other tests

  export NS_NAME="testing-attr.co"
  export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "$NS_NAME" --json | jq -r '.id')

  export KAS_URI="https://test-kas-for-attributes.com"
  export KAS_REG_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --uri "$KAS_URI" --json | jq -r '.id')
  # Generate a valid RSA public key and base64 encode (single-line)
  export PEM_B64=$(openssl genrsa 2048 2>/dev/null | openssl rsa -pubout 2>/dev/null | base64 | tr -d '\n')
  export KAS_KEY_ID="test-key-for-attr"
  export KAS_KEY_SYSTEM_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry key create --kas "$KAS_REG_ID" --key-id "$KAS_KEY_ID" --algorithm "rsa:2048" --mode "public_key" --public-key-pem "${PEM_B64}" --json | jq -r '.key.id')
  export PEM=$(echo "$PEM_B64" | base64 -d)
}

# always create a randomly named attribute
setup() {
  # invoke binary with credentials
  run_otdfctl_attr() {
    run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes $*"
  }

  export ATTR_NAME_RANDOM=$(LC_ALL=C tr -dc 'a-zA-Z' </dev/urandom | head -c 16)
  export ATTR_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes create --namespace "$NS_ID" --name "$ATTR_NAME_RANDOM" --rule ANY_OF -l key=value --json | jq -r '.id')
}

# always unsafely delete the created attribute
teardown() {
  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --force --id "$ATTR_ID"
}

teardown_file() {
  # remove the namespace
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_ID" --force
  delete_all_keys_in_kas "$KAS_REG_ID"
  delete_kas_registry "$KAS_REG_ID"

  # clear out all test env vars
  unset HOST WITH_CREDS NS_NAME NS_ID ATTR_NAME_RANDOM KAS_REG_ID KAS_KEY_ID KAS_URI KAS_KEY_SYSTEM_ID PEM PEM_B64 ATTR_ID
}

@test "Create an attribute - With Values" {
  run_otdfctl_attr create --name attrWithValues --namespace "$NS_ID" --rule HIERARCHY -v val1 -v val2 --json
  assert_success
  [ "$(echo "$output" | jq -r '.values[0].value')" = "val1" ]
  [ "$(echo "$output" | jq -r '.values[1].value')" = "val2" ]
  [ "$(echo "$output" | jq -r '.allow_traversal')" = {} ]
}

@test "Create an attribute - Allow Traversal" {
  run_otdfctl_attr create --name attrAllowTraversal --namespace "$NS_ID" --rule HIERARCHY --allow-traversal --json
  assert_success
  [ "$(echo "$output" | jq -r '.allow_traversal.value')" = true ]
}

@test "Create an attribute - Bad" {
  # bad rule
  run_otdfctl_attr create --name attr1 --namespace "$NS_ID" --rule NONEXISTENT
  assert_failure
  assert_output --partial "invalid attribute rule: NONEXISTENT, must be one of [ALL_OF, ANY_OF, HIERARCHY]"

  # missing flags
  run_otdfctl_attr create --name attr1 --rule ALL_OF
  assert_failure
  run_otdfctl_attr create --name attr1 --namespace "$NS_ID"
  assert_failure
  run_otdfctl_attr create --rule HIERARCHY --namespace "$NS_ID"
  assert_failure
}

@test "Get an attribute definition - Good" {
  LOWERED=$(echo "$ATTR_NAME_RANDOM" | awk '{print tolower($0)}')

  run_otdfctl_attr get --id "$ATTR_ID"
  assert_success
  assert_line --regexp "Id.*$ATTR_ID"
  assert_line --regexp "Name.*$LOWERED"
  assert_output --partial "ANY_OF"
  assert_line --regexp "Namespace.*$NS_NAME"
  assert_line --regexp "Allow Traversal.*false"

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.id')" = "$ATTR_ID" ]
  [ "$(echo "$output" | jq -r '.name')" = "$LOWERED" ]
  [ "$(echo "$output" | jq -r '.rule')" = 2 ]
  [ "$(echo "$output" | jq -r '.namespace.id')" = "$NS_ID" ]
  [ "$(echo "$output" | jq -r '.namespace.name')" = "$NS_NAME" ]
  [ "$(echo "$output" | jq -r '.metadata.labels.key')" = "value" ]
}

@test "Get an attribute definition - Bad" {
  # no id flag
  run_otdfctl_attr get
  assert_failure
}

@test "Update an attribute definition (Safe) - Good" {
  # replace labels
  run_otdfctl_attr update --force-replace-labels -l key=somethingElse --id "$ATTR_ID" --json
  assert_success
  [ "$(echo $output | jq -r '.metadata.labels.key')" = "somethingElse" ]

  # extend labels
  run_otdfctl_attr update -l other=testing --id "$ATTR_ID" --json
  assert_success
  [ "$(echo $output | jq -r '.metadata.labels.other')" = "testing" ]
  [ "$(echo $output | jq -r '.metadata.labels.key')" = "somethingElse" ]
}

@test "Update an attribute definition (Safe) - Bad" {
  # no id
  run_otdfctl_attr update
  assert_failure
}

@test "List attribute definitions" {
  run_otdfctl_attr list
  assert_success
  assert_output --partial "$ATTR_ID"
  assert_output --partial "Total"
  assert_line --regexp "Current Offset.*0"

  run_otdfctl_attr list --state active
  assert_success
  assert_output --partial "$ATTR_ID"
  assert_output --partial "Total"
  assert_line --regexp "Current Offset.*0"

  run_otdfctl_attr list --state inactive
  assert_success
  refute_output --partial "$ATTR_ID"
  assert_output --partial "Total"
  assert_line --regexp "Current Offset.*0"
}

@test "List - comprehensive pagination tests" {
  # create 10 random attributes so we have confidence there are >= 10 attribute definitions
  for i in {1..10}; do
    random_name=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
    run_otdfctl_attr create --name "$random_name" --namespace "$NS_ID" --rule ANY_OF
    assert_success
  done

  run_otdfctl_attr list --limit 2
  assert_success
  assert_line --regexp "Current Offset.*0"
  assert_line --regexp "Next Offset.*2"

  run_otdfctl_attr list  --limit 2 --json
  assert_success
  assert_equal $(echo "$output" | jq -r '.attributes | length') 2
  [[ $(echo "$output" | jq -r '.pagination.total') -ge 10 ]]
  assert_equal $(echo "$output" | jq -r '.pagination.next_offset') 2
  assert_equal $(echo "$output" | jq -r '.pagination.current_offset') "null"

  run_otdfctl_attr list --limit 5 --offset 2
  assert_success
  assert_line --regexp "Current Offset.*2"
  assert_line --regexp "Next Offset.*7"

  run_otdfctl_attr list --offset 2
  assert_success
  assert_line --regexp "Current Offset.*2"

  run_otdfctl_attr list --limit 500
  assert_success
  refute_output --partial "Next Offset"
}

@test "Deactivate then unsafe reactivate an attribute definition" {
  run_otdfctl_attr deactivate
  assert_failure

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.active.value')" = true ]

  run_otdfctl_attr deactivate --id "$ATTR_ID" --force
  assert_success
  assert_output --regexp "Allow Traver*"

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.active')" = {} ]

  run_otdfctl_attr unsafe reactivate
  assert_failure

  run_otdfctl_attr unsafe reactivate --id "$ATTR_ID" --force
  assert_success

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.active.value')" = true ]
}

@test "Unsafe Update an attribute definition" {
  # create with two values
  run_otdfctl_attr create --name created --namespace "$NS_ID" --rule HIERARCHY -v val1 -v val2 --json
  CREATED_ID=$(echo "$output" | jq -r '.id')
  VAL1_ID=$(echo "$output" | jq -r '.values[0].id')
  VAL2_ID=$(echo "$output" | jq -r '.values[1].id')

  run_otdfctl_attr unsafe update --name updated --id "$CREATED_ID" --json --force
  assert_success
  run_otdfctl_attr get --id "$CREATED_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.name')" = "updated" ]

  run_otdfctl_attr unsafe update --rule ALL_OF --id "$CREATED_ID" --json --force
  assert_success
  run_otdfctl_attr get --id "$CREATED_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.rule')" = 1 ]

  run_otdfctl_attr unsafe update --id "$CREATED_ID" --json --values-order "$VAL2_ID" --values-order "$VAL1_ID" --force
  assert_success
  run_otdfctl_attr get --id "$CREATED_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.values[0].value')" = "val2" ]
  [ "$(echo "$output" | jq -r '.values[1].value')" = "val1" ]

  # ensure non-JSON output reflects reordered values immediately
  run_otdfctl_attr unsafe update --id "$CREATED_ID" --values-order "$VAL1_ID" --values-order "$VAL2_ID" --force
  assert_success
  assert_line --regexp "Value IDs\\s+│\\[$VAL1_ID, $VAL2_ID\\]"

  run_otdfctl_attr unsafe update --id "$CREATED_ID" --allow-traversal --json --force
  assert_success
  run_otdfctl_attr get --id "$CREATED_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.allow_traversal.value')" = true ]
}

@test "Unsafe Update preserves allow traversal when unchanged" {
  run_otdfctl_attr create --name attr-allow-traversal-update --namespace "$NS_ID" --rule HIERARCHY --allow-traversal --json
  assert_success
  CREATED_ID=$(echo "$output" | jq -r '.id')

  run_otdfctl_attr unsafe update --id "$CREATED_ID" --name updated-name --json --force
  assert_success
  run_otdfctl_attr get --id "$CREATED_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.allow_traversal.value')" = true ]

  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --force --id "$CREATED_ID"
}

@test "Unsafe Update can disallow traversal" {
  run_otdfctl_attr create --name attr-disallow-traversal-update --namespace "$NS_ID" --rule HIERARCHY --allow-traversal --json
  assert_success
  CREATED_ID=$(echo "$output" | jq -r '.id')

  run_otdfctl_attr unsafe update --id "$CREATED_ID" --allow-traversal=false --json --force
  assert_success
  run_otdfctl_attr get --id "$CREATED_ID" --json
  assert_success
  [ "$(echo "$output" | jq -r '.allow_traversal')" = {} ]

  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --force --id "$CREATED_ID"
}

@test "Assign/Remove KAS key from attribute definition - With Attribute Id" {
  # Test assigning KAS key to attribute
  run_otdfctl_attr key assign --attribute "$ATTR_ID" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.attribute_id')" "$ATTR_ID"
  assert_equal "$(echo "$output" | jq -r '.key_id')" "$KAS_KEY_SYSTEM_ID"

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$ATTR_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_uri')" "$KAS_URI"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_id')" "$KAS_REG_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.pem')" "${PEM}"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.algorithm')" 1
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.kid')" "$KAS_KEY_ID"

  # Assign the key to the attribute
  run_otdfctl_attr key remove --attribute "$ATTR_ID" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_success

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$ATTR_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0
}

@test "Assign/Remove KAS key from attribute definition - With Attribute FQN" {
  # Test assigning KAS key to attribute
  # Get the attribute by ID to retrieve its FQN
  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.keys | length')" 0
  ATTR_FQN=$(echo "$output" | jq -r '.fqn')

  run_otdfctl_attr key assign --attribute "$ATTR_FQN" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.attribute_id')" "$ATTR_ID"
  assert_equal "$(echo "$output" | jq -r '.key_id')" "$KAS_KEY_SYSTEM_ID"

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$ATTR_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_uri')" "$KAS_URI"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_id')" "$KAS_REG_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.pem')" "$PEM"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.algorithm')" 1
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.kid')" "$KAS_KEY_ID"

  # Assign the key to the attribute
  run_otdfctl_attr key remove --attribute "$ATTR_FQN" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_success

  run_otdfctl_attr get --id "$ATTR_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$ATTR_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0
}

@test "Assign/Remove KAS key from attribute value - With Value Id" {
  # Create attribute with a value
  run_otdfctl_attr create --name attr-with-value-2 --namespace "$NS_ID" --rule HIERARCHY -v test-value --json
  assert_success
  ATTR_WITH_VALUE_ID=$(echo "$output" | jq -r '.id')
  VALUE_ID=$(echo "$output" | jq -r '.values[0].id')

  # Test assigning KAS key to attribute value
  run_otdfctl_attr values key assign --value "$VALUE_ID" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.value_id')" "$VALUE_ID"
  assert_equal "$(echo "$output" | jq -r '.key_id')" "$KAS_KEY_SYSTEM_ID"

  run_otdfctl_attr values get --id "$VALUE_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$VALUE_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_uri')" "$KAS_URI"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_id')" "$KAS_REG_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.pem')" "$PEM"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.algorithm')" 1
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.kid')" "$KAS_KEY_ID"

  # Remove key from attribute value
  run_otdfctl_attr values key remove --value "$VALUE_ID" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_success

  run_otdfctl_attr values get --id "$VALUE_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$VALUE_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0

  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --force --id "$ATTR_WITH_VALUE_ID"
}

@test "Assign/Remove KAS key from attribute value - With Value FQN" {
  # Create attribute with a value
  run_otdfctl_attr create --name attr-with-value-2 --namespace "$NS_ID" --rule HIERARCHY -v test-value --json
  assert_success
  ATTR_WITH_VALUE_ID=$(echo "$output" | jq -r '.id')
  VALUE_FQN=$(echo "$output" | jq -r '.values[0].fqn')
  VALUE_ID=$(echo "$output" | jq -r '.values[0].id')

  # Assign with value FQN
  run_otdfctl_attr values key assign --value "$VALUE_FQN" --key-id "$KAS_KEY_SYSTEM_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.value_id')" "$VALUE_ID"
  assert_equal "$(echo "$output" | jq -r '.key_id')" "$KAS_KEY_SYSTEM_ID"

  run_otdfctl_attr values get --id "$VALUE_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$VALUE_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_uri')" "$KAS_URI"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].kas_id')" "$KAS_REG_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.pem')" "$PEM"
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.algorithm')" 1
  assert_equal "$(echo "$output" | jq -r '.kas_keys[0].public_key.kid')" "$KAS_KEY_ID"

  # Remove key from attribute value by FQN
  run_otdfctl_attr values key remove --value "$VALUE_FQN" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_success

  run_otdfctl_attr values get --id "$VALUE_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.id')" "$VALUE_ID"
  assert_equal "$(echo "$output" | jq -r '.kas_keys | length')" 0

  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --force --id "$ATTR_WITH_VALUE_ID"
}

@test "KAS key assignment error handling - attribute" {

  # Test with non-existent attribute ID
  run_otdfctl_attr key assign --attribute "00000000-0000-0000-0000-000000000000" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_failure
  assert_output --partial "ERROR"

  # Test with missing required flags
  run_otdfctl_attr key assign --attribute "$ATTR_ID"
  assert_failure
  assert_output --partial "Flag '--key-id' is required"

  run_otdfctl_attr key assign --key-id "$KAS_KEY_SYSTEM_ID"
  assert_failure
  assert_output --partial "Flag '--attribute' is required"
}

@test "KAS key assignment error handling - attribute value" {
  # Test with non-existent value ID
  run_otdfctl_attr values key assign --value "00000000-0000-0000-0000-000000000000" --key-id "$KAS_KEY_SYSTEM_ID"
  assert_failure
  assert_output --partial "ERROR"

  # Test with missing required flags
  run_otdfctl_attr values key assign --key-id "$KAS_KEY_SYSTEM_ID"
  assert_failure
  assert_output --partial "Flag '--value' is required"

  run_otdfctl_attr values key assign --value "00000000-0000-0000-0000-000000000000"
  assert_failure
  assert_output --partial "Flag '--key-id' is required"
}

@test "List attribute values - Good" {
  # Create an attribute with multiple values for testing
  run_otdfctl_attr create --name attr-with-values-list --namespace "$NS_ID" --rule HIERARCHY -v vala -v valb -v valc --json
  assert_success
  ATTR_WITH_VALUES_ID=$(echo "$output" | jq -r '.id')
  VALUE1_ID=$(echo "$output" | jq -r '.values[0].id')
  VALUE2_ID=$(echo "$output" | jq -r '.values[1].id')
  VALUE3_ID=$(echo "$output" | jq -r '.values[2].id')

  # Test with JSON output
  run_otdfctl_attr values list --attribute-id "$ATTR_WITH_VALUES_ID" --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.values | length')" 3
  assert_output --partial "vala"
  assert_output --partial "valb"
  assert_output --partial "valc"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" 3
  assert_equal "$(echo "$output" | jq -r '.pagination.current_offset')" "null"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "null"

  # Test state filtering - all values should be active by default
  run_otdfctl_attr values list --attribute-id "$ATTR_WITH_VALUES_ID" --state active
  assert_success
  assert_output --partial "$VALUE1_ID"
  assert_output --partial "$VALUE2_ID"
  assert_output --partial "$VALUE3_ID"

  # Test state filtering - inactive (should be empty since all values are active)
  run_otdfctl_attr values list --attribute-id "$ATTR_WITH_VALUES_ID" --state inactive
  assert_success
  refute_output --partial "$VALUE1_ID"
  refute_output --partial "$VALUE2_ID"
  refute_output --partial "$VALUE3_ID"

  # Test pagination with limit and JQ verification
  run_otdfctl_attr values list --attribute-id "$ATTR_WITH_VALUES_ID" --limit 2 --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.values | length')" "2"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" "3"
  assert_equal "$(echo "$output" | jq -r '.pagination.current_offset')" "null"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "2"

  # Test pagination with offset and JQ verification
  run_otdfctl_attr values list --attribute-id "$ATTR_WITH_VALUES_ID" --limit 2 --offset 1 --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.values | length')" "2"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" "3"
  assert_equal "$(echo "$output" | jq -r '.pagination.current_offset')" "1"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "null"

  # Test pagination at the end (no next offset)
  run_otdfctl_attr values list --attribute-id "$ATTR_WITH_VALUES_ID" --limit 1 --offset 2 --json
  assert_success
  assert_equal "$(echo "$output" | jq -r '.values | length')" "1"
  assert_equal "$(echo "$output" | jq -r '.pagination.total')" "3"
  assert_equal "$(echo "$output" | jq -r '.pagination.current_offset')" "2"
  assert_equal "$(echo "$output" | jq -r '.pagination.next_offset')" "null"

  # Cleanup
  ./otdfctl $HOST $WITH_CREDS policy attributes unsafe delete --force --id "$ATTR_WITH_VALUES_ID"
}

@test "List attribute values - Bad" {
  # Test with missing required flag
  run_otdfctl_attr values list
  assert_failure
  assert_output --partial "Flag '--attribute-id' is required"

  # Test with invalid attribute ID format
  run_otdfctl_attr values list --attribute-id "invalid-id"
  assert_failure
  assert_output --partial "must be a valid UUID"
}
