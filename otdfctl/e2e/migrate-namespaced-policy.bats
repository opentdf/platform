#!/usr/bin/env bats

# bats file_tags=namespaced_policy_migration

# Tests for namespaced-policy migration
# This file needs isolated execution while the rest of otdfctl/e2e is still
# running in parallel. The migration planner discovers legacy/global policy
# objects by scope, so overlapping unnamespaced fixtures from other BATS files
# can pollute these migration assertions.
# CI should run this tag in a separate invocation, then run the remaining suite
# with this tag filtered out.

load "${BATS_LIB_PATH}/bats-support/load.bash"
load "${BATS_LIB_PATH}/bats-assert/load.bash"

run_otdfctl_migrate() {
  run sh -c "./otdfctl $HOST $WITH_CREDS migrate $*"
}

run_otdfctl_action() {
  run sh -c "./otdfctl $HOST $WITH_CREDS policy actions $*"
}

run_otdfctl_sm() {
  run sh -c "./otdfctl $HOST $WITH_CREDS policy subject-mappings $*"
}

action_plan_source_id() {
  local output_file="$1"
  local action_name="$2"
  jq -er --arg action_name "$action_name" '
    .actions[]
    | select(.source.name == $action_name)
    | .source.id
  ' "$output_file"
}

action_plan_target_count() {
  local output_file="$1"
  local action_name="$2"
  jq -er --arg action_name "$action_name" '
    [
      .actions[]
      | select(.source.name == $action_name)
      | .targets[]
    ] | length
  ' "$output_file"
}

action_plan_target_status() {
  local output_file="$1"
  local action_name="$2"
  local namespace_fqn="$3"
  jq -er --arg action_name "$action_name" --arg namespace_fqn "$namespace_fqn" '
    .actions[]
    | select(.source.name == $action_name)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | .status
  ' "$output_file"
}

action_plan_target_effective_id() {
  local output_file="$1"
  local action_name="$2"
  local namespace_fqn="$3"
  jq -er --arg action_name "$action_name" --arg namespace_fqn "$namespace_fqn" '
    .actions[]
    | select(.source.name == $action_name)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | (.execution.created_target_id // .existing.id // empty)
  ' "$output_file"
}

assert_action_target_count() {
  local output_file="$1"
  local action_name="$2"
  local expected_count="$3"

  run action_plan_target_count "$output_file" "$action_name"
  assert_success
  assert_equal "$output" "$expected_count"
}

assert_action_target_absent() {
  local output_file="$1"
  local action_name="$2"
  local namespace_fqn="$3"

  run jq -e --arg action_name "$action_name" --arg namespace_fqn "$namespace_fqn" '
    .actions[]
    | select(.source.name == $action_name)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
  ' "$output_file"
  assert_failure
}

assert_standard_action_resolved_in_namespace() {
  local output_file="$1"
  local action_name="$2"
  local namespace_id="$3"
  local namespace_fqn="$4"

  run action_plan_target_status "$output_file" "$action_name" "$namespace_fqn"
  assert_success
  assert_equal "$output" "existing_standard"

  local planned_target_id
  planned_target_id=$(action_plan_target_effective_id "$output_file" "$action_name" "$namespace_fqn")
  assert_not_equal "$planned_target_id" ""

  local live_target_id
  live_target_id=$(./otdfctl $HOST $WITH_CREDS policy actions get --name "$action_name" --namespace "$namespace_id" --json | jq -r '.id')
  assert_not_equal "$live_target_id" ""

  assert_equal "$planned_target_id" "$live_target_id"
}

assert_custom_action_created_in_namespace() {
  local output_file="$1"
  local action_name="$2"
  local source_action_id="$3"
  local namespace_id="$4"
  local namespace_fqn="$5"

  run action_plan_target_status "$output_file" "$action_name" "$namespace_fqn"
  assert_success
  assert_equal "$output" "create"

  local created_target_id
  created_target_id=$(action_plan_target_effective_id "$output_file" "$action_name" "$namespace_fqn")
  assert_not_equal "$created_target_id" ""

  local created_action_json
  created_action_json=$(./otdfctl $HOST $WITH_CREDS policy actions get --id "$created_target_id" --json)

  assert_equal "$(echo "$created_action_json" | jq -r '.id')" "$created_target_id"
  assert_equal "$(echo "$created_action_json" | jq -r '.name')" "$action_name"
  assert_equal "$(echo "$created_action_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$created_action_json" | jq -r '.metadata.labels.migrated_from')" "$source_action_id"
  assert_not_equal "$(echo "$created_action_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_legacy_custom_action_still_exists() {
  local action_id="$1"
  local action_name="$2"

  local legacy_action_json
  legacy_action_json=$(./otdfctl $HOST $WITH_CREDS policy actions get --id "$action_id" --json)

  assert_equal "$(echo "$legacy_action_json" | jq -r '.id')" "$action_id"
  assert_equal "$(echo "$legacy_action_json" | jq -r '.name')" "$action_name"
  assert_equal "$(echo "$legacy_action_json" | jq -r '.namespace.id // empty')" ""
}

run_namespaced_policy_commit() {
  local scope="$1"
  local output_file="$2"

  run_otdfctl_migrate --commit namespaced-policy --scope "$scope" --output "$output_file"
}

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  export MIGRATION_TEST_PREFIX="np-actions-$(date +%s)"
  export MIGRATION_OUTPUT_DIR="/tmp/${MIGRATION_TEST_PREFIX}"
  mkdir -p "$MIGRATION_OUTPUT_DIR"

  export NS_A_NAME="${MIGRATION_TEST_PREFIX}-a.test"
  export NS_B_NAME="${MIGRATION_TEST_PREFIX}-b.test"
  export NS_A_FQN="https://${NS_A_NAME}"
  export NS_B_FQN="https://${NS_B_NAME}"

  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name \"$NS_A_NAME\" --json"
  assert_success
  export NS_A_ID=$(echo "$output" | jq -r '.id')
  assert_not_equal "$NS_A_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name \"$NS_B_NAME\" --json"
  assert_success
  export NS_B_ID=$(echo "$output" | jq -r '.id')
  assert_not_equal "$NS_B_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes create --name \"${MIGRATION_TEST_PREFIX}-attr-a\" --namespace \"$NS_A_ID\" --rule ANY_OF -v \"${MIGRATION_TEST_PREFIX}-a1\" --json"
  assert_success
  attr_a_json="$output"
  export ATTR_A_ID=$(echo "$attr_a_json" | jq -r '.id')
  export ATTR_A_VAL_1_ID=$(echo "$attr_a_json" | jq -r '.values[0].id')
  assert_not_equal "$ATTR_A_ID" ""
  assert_not_equal "$ATTR_A_VAL_1_ID" ""

  # ATTR_A values resolve under the namespace FQN:
  #   ${NS_A_FQN}/attr/${MIGRATION_TEST_PREFIX}-attr-a/value/${MIGRATION_TEST_PREFIX}-a1
  #   ${NS_A_FQN}/attr/${MIGRATION_TEST_PREFIX}-attr-a/value/${MIGRATION_TEST_PREFIX}-a2
  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes values create --attribute-id \"$ATTR_A_ID\" --value \"${MIGRATION_TEST_PREFIX}-a2\" --json"
  assert_success
  export ATTR_A_VAL_2_ID=$(echo "$output" | jq -r '.id')
  assert_not_equal "$ATTR_A_VAL_2_ID" ""

  # ATTR_B values resolve under the namespace FQN:
  #   ${NS_B_FQN}/attr/${MIGRATION_TEST_PREFIX}-attr-b/value/${MIGRATION_TEST_PREFIX}-b1
  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes create --name \"${MIGRATION_TEST_PREFIX}-attr-b\" --namespace \"$NS_B_ID\" --rule ANY_OF -v \"${MIGRATION_TEST_PREFIX}-b1\" --json"
  assert_success
  attr_b_json="$output"
  export ATTR_B_ID=$(echo "$attr_b_json" | jq -r '.id')
  export ATTR_B_VAL_1_ID=$(echo "$attr_b_json" | jq -r '.values[0].id')
  assert_not_equal "$ATTR_B_ID" ""
  assert_not_equal "$ATTR_B_VAL_1_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy actions get --name read --json"
  assert_success
  export GLOBAL_READ_ID=$(echo "$output" | jq -r '.id')
  assert_not_equal "$GLOBAL_READ_ID" ""

  export CUSTOM_ACTION_NAME="${MIGRATION_TEST_PREFIX}-download"
  run sh -c "./otdfctl $HOST $WITH_CREDS policy actions create --name \"$CUSTOM_ACTION_NAME\" --json"
  assert_success
  export CUSTOM_ACTION_ID=$(echo "$output" | jq -r '.id')
  assert_not_equal "$CUSTOM_ACTION_ID" ""

  export SHARED_SCS='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["engineering"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  run sh -c "./otdfctl $HOST $WITH_CREDS policy scs create --subject-sets '$SHARED_SCS' --json"
  assert_success
  export SHARED_SCS_ID=$(echo "$output" | jq -r '.id')
  assert_not_equal "$SHARED_SCS_ID" ""

  # These anchor subject mappings stay legacy/global. Their target namespace
  # should be derived from the referenced attribute value during migration.
  run sh -c "./otdfctl $HOST $WITH_CREDS policy subject-mappings create --attribute-value-id \"$ATTR_A_VAL_1_ID\" --action \"$GLOBAL_READ_ID\" --subject-condition-set-id \"$SHARED_SCS_ID\" --json"
  assert_success
  sm_read_a_json="$output"
  export SM_READ_A_ID=$(echo "$sm_read_a_json" | jq -r '.id')
  assert_not_equal "$SM_READ_A_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy subject-mappings create --attribute-value-id \"$ATTR_A_VAL_2_ID\" --action \"$CUSTOM_ACTION_ID\" --subject-condition-set-id \"$SHARED_SCS_ID\" --json"
  assert_success
  sm_download_a_json="$output"
  export SM_DOWNLOAD_A_ID=$(echo "$sm_download_a_json" | jq -r '.id')
  assert_not_equal "$SM_DOWNLOAD_A_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy subject-mappings create --attribute-value-id \"$ATTR_B_VAL_1_ID\" --action \"$GLOBAL_READ_ID\" --subject-condition-set-id \"$SHARED_SCS_ID\" --json"
  assert_success
  sm_read_b_json="$output"
  export SM_READ_B_ID=$(echo "$sm_read_b_json" | jq -r '.id')
  assert_not_equal "$SM_READ_B_ID" ""
}

teardown_file() {
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_A_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_B_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy scs delete --id "$SHARED_SCS_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy actions delete --id "$CUSTOM_ACTION_ID" --force

  rm -rf "$MIGRATION_OUTPUT_DIR"

  unset HOST WITH_CREDS MIGRATION_TEST_PREFIX MIGRATION_OUTPUT_DIR
  unset NS_A_NAME NS_B_NAME NS_A_FQN NS_B_FQN NS_A_ID NS_B_ID
  unset ATTR_A_ID ATTR_A_VAL_1_ID ATTR_A_VAL_2_ID ATTR_B_ID ATTR_B_VAL_1_ID
  unset GLOBAL_READ_ID CUSTOM_ACTION_NAME CUSTOM_ACTION_ID SHARED_SCS SHARED_SCS_ID
  unset SM_READ_A_ID SM_DOWNLOAD_A_ID SM_READ_B_ID
}

@test "migrate namespaced-policy actions resolves standard actions and creates custom actions" {
  local output_file="${MIGRATION_OUTPUT_DIR}/actions-plan.json"

  run_namespaced_policy_commit "actions" "$output_file"
  assert_success

  assert_action_target_count "$output_file" "read" 2
  assert_standard_action_resolved_in_namespace "$output_file" "read" "$NS_A_ID" "$NS_A_FQN"
  assert_standard_action_resolved_in_namespace "$output_file" "read" "$NS_B_ID" "$NS_B_FQN"

  assert_action_target_count "$output_file" "$CUSTOM_ACTION_NAME" 1
  source_action_id=$(action_plan_source_id "$output_file" "$CUSTOM_ACTION_NAME")
  assert_equal "$source_action_id" "$CUSTOM_ACTION_ID"
  assert_custom_action_created_in_namespace "$output_file" "$CUSTOM_ACTION_NAME" "$CUSTOM_ACTION_ID" "$NS_A_ID" "$NS_A_FQN"
  assert_action_target_absent "$output_file" "$CUSTOM_ACTION_NAME" "$NS_B_FQN"

  assert_legacy_custom_action_still_exists "$CUSTOM_ACTION_ID" "$CUSTOM_ACTION_NAME"
}
