#!/usr/bin/env bats

# Tests for KAS grants

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  export KAS_URI="https://e2etestkas.com"
  export KAS_ID=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --uri "$KAS_URI" --json | jq -r '.id')
  export KAS_ID_FLAG="--kas-id $KAS_ID"

  export NS_ID=$(./otdfctl $HOST $WITH_CREDS policy attributes namespaces create -n "testing-kasg.uk" --json | jq -r '.id')
  ATTR=$(./otdfctl $HOST $WITH_CREDS policy attributes create -n "attr1" --json --rule ANY_OF --namespace "$NS_ID" -v "val1")
  export ATTR_ID=$(echo $ATTR | jq -r '.id')
  export VAL_ID=$(echo $ATTR | jq -r '.values[0].id')
}

setup() {
  load "${BATS_LIB_PATH}/bats-support/load.bash"
  load "${BATS_LIB_PATH}/bats-assert/load.bash"

  # invoke binary with credentials
  run_otdfctl_kasg() {
    run sh -c "./otdfctl $HOST $WITH_CREDS policy kas-grants $*"
  }
}

teardown_file() {
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy kas-registry delete --id "$KAS_ID" --force

  # clear out all test env vars
  unset HOST WITH_CREDS KAS_ID KAS_ID_FLAG KAS_URI NS_ID NS_ID_FLAG ATTR_ID ATTR_ID_FLAG VAL_ID VAL_ID_FLAG
}

@test "unassign rejects more than one type of grant at once" {
  export NS_ID_FLAG='--namespace-id 258e69b7-9e61-46e1-8fd6-b4ba00898ec2'
  export ATTR_ID_FLAG='--attribute-id 258e69b7-9e61-46e1-8fd6-b4ba00898ec1'
  export VAL_ID_FLAG='--value-id 258e69b7-9e61-46e1-8fd6-b4ba00898ec3'

  run_otdfctl_kasg unassign $ATTR_ID_FLAG $VAL_ID_FLAG $KAS_ID_FLAG
  assert_failure
  assert_output --partial "Must specify exactly one Attribute Namespace ID, Definition ID, or Value ID to unassign"

  run_otdfctl_kasg unassign $NS_ID_FLAG $VAL_ID_FLAG $KAS_ID_FLAG
  assert_failure
  assert_output --partial "Must specify exactly one Attribute Namespace ID, Definition ID, or Value ID to unassign"

  run_otdfctl_kasg unassign $ATTR_ID_FLAG $NS_ID_FLAG $KAS_ID_FLAG
  assert_failure
  assert_output --partial "Must specify exactly one Attribute Namespace ID, Definition ID, or Value ID to unassign"
}

@test "assign grant prints warning" {
  # assign the namespace a grant
  export NS_ID_FLAG="--namespace-id $NS_ID"

  run_otdfctl_kasg assign "$NS_ID_FLAG" "$KAS_ID_FLAG"
  assert_output --partial "Grants are now Key Mappings."

  run_otdfctl_kasg unassign "$NS_ID_FLAG" "$KAS_ID_FLAG"
  assert_output --partial "Grants are now Key Mappings."
}

@test "optional ID flag string error message" {
  export NS_ID_FLAG='--namespace-id hello'
  export ATTR_ID_FLAG='--attribute-id world'
  export VAL_ID_FLAG='--value-id goodnight'

  run_otdfctl_kasg unassign $NS_ID_FLAG $KAS_ID_FLAG
  assert_failure
  assert_output --partial "Optional flag '--namespace-id' received value 'hello' and must be a valid UUID if used"

  run_otdfctl_kasg unassign $ATTR_ID_FLAG $KAS_ID_FLAG
  assert_failure
  assert_output --partial "Optional flag '--attribute-id' received value 'world' and must be a valid UUID if used"

  run_otdfctl_kasg unassign $VAL_ID_FLAG $KAS_ID_FLAG
  assert_failure
  assert_output --partial "Optional flag '--value-id' received value 'goodnight' and must be a valid UUID if used"
}
