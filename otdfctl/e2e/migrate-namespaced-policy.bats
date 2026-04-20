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
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json migrate "$@"
}

run_otdfctl_action() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy actions "$@"
}

run_otdfctl_sm() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy subject-mappings "$@"
}

run_otdfctl_scs() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy scs "$@"
}

track_action_id() {
  local action_id="$1"
  TRACKED_ACTION_IDS="${TRACKED_ACTION_IDS}${action_id}"$'\n'
}

track_scs_id() {
  local scs_id="$1"
  TRACKED_SCS_IDS="${TRACKED_SCS_IDS}${scs_id}"$'\n'
}

track_subject_mapping_id() {
  local subject_mapping_id="$1"
  TRACKED_SUBJECT_MAPPING_IDS="${TRACKED_SUBJECT_MAPPING_IDS}${subject_mapping_id}"$'\n'
}

create_global_action() {
  local result_var="$1"
  local action_name="$2"
  shift 2

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy actions create --name "$action_name" "$@" --json
  assert_success

  local action_id
  action_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$action_id" ""

  track_action_id "$action_id"
  printf -v "$result_var" '%s' "$action_id"
}

create_global_scs() {
  local result_var="$1"
  local subject_sets_json="$2"
  shift 2

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy scs create --subject-sets "$subject_sets_json" "$@" --json
  assert_success

  local scs_id
  scs_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$scs_id" ""

  track_scs_id "$scs_id"
  printf -v "$result_var" '%s' "$scs_id"
}

create_namespaced_scs() {
  local result_var="$1"
  local namespace_id="$2"
  local subject_sets_json="$3"
  shift 3

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy scs create --namespace "$namespace_id" --subject-sets "$subject_sets_json" "$@" --json
  assert_success

  local scs_id
  scs_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$scs_id" ""

  track_scs_id "$scs_id"
  printf -v "$result_var" '%s' "$scs_id"
}

create_legacy_subject_mapping() {
  local result_var="$1"
  local attribute_value_id="$2"
  local action_id="$3"
  local subject_condition_set_id="$4"
  shift 4

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy subject-mappings create --attribute-value-id "$attribute_value_id" --action "$action_id" --subject-condition-set-id "$subject_condition_set_id" "$@" --json
  assert_success

  local subject_mapping_id
  subject_mapping_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$subject_mapping_id" ""

  track_subject_mapping_id "$subject_mapping_id"
  printf -v "$result_var" '%s' "$subject_mapping_id"
}

subject_mapping_plan_target_count() {
  local output_file="$1"
  local source_mapping_id="$2"
  jq -er --arg source_mapping_id "$source_mapping_id" '
    [
      .subject_mappings[]
      | select(.source.id == $source_mapping_id)
      | .targets[]
    ] | length
  ' "$output_file"
}

subject_mapping_plan_target_status() {
  local output_file="$1"
  local source_mapping_id="$2"
  local namespace_fqn="$3"
  jq -er --arg source_mapping_id "$source_mapping_id" --arg namespace_fqn "$namespace_fqn" '
    .subject_mappings[]
    | select(.source.id == $source_mapping_id)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | .status
  ' "$output_file"
}

subject_mapping_plan_target_effective_id() {
  local output_file="$1"
  local source_mapping_id="$2"
  local namespace_fqn="$3"
  jq -er --arg source_mapping_id "$source_mapping_id" --arg namespace_fqn "$namespace_fqn" '
    .subject_mappings[]
    | select(.source.id == $source_mapping_id)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | (.execution.created_target_id // .existing.id // empty)
  ' "$output_file"
}

subject_mapping_plan_action_status() {
  local output_file="$1"
  local source_mapping_id="$2"
  local namespace_fqn="$3"
  local source_action_id="$4"
  jq -er --arg source_mapping_id "$source_mapping_id" --arg namespace_fqn "$namespace_fqn" --arg source_action_id "$source_action_id" '
    .subject_mappings[]
    | select(.source.id == $source_mapping_id)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | .actions[]
    | select(.source_id == $source_action_id)
    | .status
  ' "$output_file"
}

subject_mapping_plan_scs_status() {
  local output_file="$1"
  local source_mapping_id="$2"
  local namespace_fqn="$3"
  jq -er --arg source_mapping_id "$source_mapping_id" --arg namespace_fqn "$namespace_fqn" '
    .subject_mappings[]
    | select(.source.id == $source_mapping_id)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | .subject_condition_set.status
  ' "$output_file"
}

assert_subject_mapping_target_count() {
  local output_file="$1"
  local source_mapping_id="$2"
  local expected_count="$3"

  run subject_mapping_plan_target_count "$output_file" "$source_mapping_id"
  assert_success
  assert_equal "$output" "$expected_count"
}

assert_subject_mapping_created_in_namespace() {
  local output_file="$1"
  local source_mapping_id="$2"
  local namespace_id="$3"
  local namespace_fqn="$4"
  local attribute_value_id="$5"
  local action_name="$6"
  local source_action_id="$7"
  local expected_action_status="$8"
  local expected_action_count="$9"
  local source_scs_id="${10}"
  local expected_scs_count="${11}"

  run subject_mapping_plan_target_status "$output_file" "$source_mapping_id" "$namespace_fqn"
  assert_success
  assert_equal "$output" "create"

  assert_action_target_count "$output_file" "$action_name" "$expected_action_count"
  case "$expected_action_status" in
    create)
      assert_custom_action_created_in_namespace "$output_file" "$action_name" "$source_action_id" "$namespace_id" "$namespace_fqn"
      ;;
    existing_standard)
      assert_standard_action_resolved_in_namespace "$output_file" "$action_name" "$namespace_id" "$namespace_fqn"
      ;;
    *)
      false
      ;;
  esac

  run subject_mapping_plan_action_status "$output_file" "$source_mapping_id" "$namespace_fqn" "$source_action_id"
  assert_success
  assert_equal "$output" "$expected_action_status"

  local expected_action_target_id
  expected_action_target_id=$(action_plan_target_effective_id "$output_file" "$action_name" "$namespace_fqn")
  assert_not_equal "$expected_action_target_id" ""

  assert_scs_target_count "$output_file" "$source_scs_id" "$expected_scs_count"
  assert_scs_created_in_namespace "$output_file" "$source_scs_id" "$namespace_id" "$namespace_fqn"

  run subject_mapping_plan_scs_status "$output_file" "$source_mapping_id" "$namespace_fqn"
  assert_success
  assert_equal "$output" "create"

  local expected_scs_target_id
  expected_scs_target_id=$(scs_plan_target_effective_id "$output_file" "$source_scs_id" "$namespace_fqn")
  assert_not_equal "$expected_scs_target_id" ""

  local created_target_id
  created_target_id=$(subject_mapping_plan_target_effective_id "$output_file" "$source_mapping_id" "$namespace_fqn")
  assert_not_equal "$created_target_id" ""

  local source_mapping_json
  source_mapping_json=$(./otdfctl $HOST $WITH_CREDS policy subject-mappings get --id "$source_mapping_id" --json)

  local created_mapping_json
  created_mapping_json=$(./otdfctl $HOST $WITH_CREDS policy subject-mappings get --id "$created_target_id" --json)

  assert_equal "$(echo "$created_mapping_json" | jq -r '.id')" "$created_target_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.attribute_value.id')" "$attribute_value_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.actions[0].id')" "$expected_action_target_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.subject_condition_set.id')" "$expected_scs_target_id"
  assert_metadata_labels_preserved "$source_mapping_json" "$created_mapping_json"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.metadata.labels.migrated_from')" "$source_mapping_id"
  assert_not_equal "$(echo "$created_mapping_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_subject_mapping_already_migrated_in_namespace() {
  local output_file="$1"
  local source_mapping_id="$2"
  local namespace_id="$3"
  local namespace_fqn="$4"
  local existing_mapping_id="$5"

  assert_not_equal "$existing_mapping_id" ""

  run subject_mapping_plan_target_status "$output_file" "$source_mapping_id" "$namespace_fqn"
  assert_success
  assert_equal "$output" "already_migrated"

  local effective_target_id
  effective_target_id=$(subject_mapping_plan_target_effective_id "$output_file" "$source_mapping_id" "$namespace_fqn")
  assert_not_equal "$effective_target_id" ""
  assert_equal "$effective_target_id" "$existing_mapping_id"

  local existing_mapping_json
  existing_mapping_json=$(./otdfctl $HOST $WITH_CREDS policy subject-mappings get --id "$existing_mapping_id" --json)

  assert_equal "$(echo "$existing_mapping_json" | jq -r '.id // empty')" "$existing_mapping_id"
  assert_equal "$(echo "$existing_mapping_json" | jq -r '.namespace.id')" "$namespace_id"
}

assert_legacy_subject_mapping_still_exists() {
  local attribute_value_id="$1"
  local source_mapping_id="$2"

  assert_not_equal "$attribute_value_id" ""
  assert_not_equal "$source_mapping_id" ""

  local legacy_mapping_json
  legacy_mapping_json=$(./otdfctl $HOST $WITH_CREDS policy subject-mappings get --id "$source_mapping_id" --json)

  assert_equal "$(echo "$legacy_mapping_json" | jq -r '.id // empty')" "$source_mapping_id"
  assert_equal "$(echo "$legacy_mapping_json" | jq -r '.namespace.id // empty')" ""
  assert_equal "$(echo "$legacy_mapping_json" | jq -r '.attribute_value.id')" "$attribute_value_id"
}

assert_no_subject_mappings_in_namespace() {
  local namespace_id="$1"

  run sh -c "./otdfctl $HOST $WITH_CREDS policy subject-mappings list --namespace \"$namespace_id\" --json"
  assert_success
  assert_equal "$(echo "$output" | jq -r '.subject_mappings | length')" "0"
}

assert_metadata_labels_preserved() {
  local source_json="$1"
  local target_json="$2"

  local source_labels
  source_labels=$(echo "$source_json" | jq -c '.metadata.labels // {}')
  assert_not_equal "$source_labels" "{}"

  local target_labels
  target_labels=$(echo "$target_json" | jq -c '(.metadata.labels // {}) | del(.migrated_from, .migration_run)')

  assert_equal "$target_labels" "$source_labels"
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

scs_plan_target_count() {
  local output_file="$1"
  local source_scs_id="$2"
  jq -er --arg source_scs_id "$source_scs_id" '
    [
      .subject_condition_sets[]
      | select(.source.id == $source_scs_id)
      | .targets[]
    ] | length
  ' "$output_file"
}

scs_plan_target_status() {
  local output_file="$1"
  local source_scs_id="$2"
  local namespace_fqn="$3"
  jq -er --arg source_scs_id "$source_scs_id" --arg namespace_fqn "$namespace_fqn" '
    .subject_condition_sets[]
    | select(.source.id == $source_scs_id)
    | .targets[]
    | select(.namespace.fqn == $namespace_fqn)
    | .status
  ' "$output_file"
}

scs_plan_target_effective_id() {
  local output_file="$1"
  local source_scs_id="$2"
  local namespace_fqn="$3"
  jq -er --arg source_scs_id "$source_scs_id" --arg namespace_fqn "$namespace_fqn" '
    .subject_condition_sets[]
    | select(.source.id == $source_scs_id)
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

assert_scs_target_count() {
  local output_file="$1"
  local source_scs_id="$2"
  local expected_count="$3"

  run scs_plan_target_count "$output_file" "$source_scs_id"
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

assert_scs_target_absent() {
  local output_file="$1"
  local source_scs_id="$2"
  local namespace_fqn="$3"

  run jq -e --arg source_scs_id "$source_scs_id" --arg namespace_fqn "$namespace_fqn" '
    .subject_condition_sets[]
    | select(.source.id == $source_scs_id)
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
  live_target_id=$(./otdfctl $HOST $WITH_CREDS policy actions get --name "$action_name" --namespace "$namespace_id" --json | jq -r '.id // empty')
  assert_not_equal "$live_target_id" ""

  assert_equal "$planned_target_id" "$live_target_id"
}

assert_action_already_migrated_in_namespace() {
  local output_file="$1"
  local action_name="$2"
  local namespace_id="$3"
  local namespace_fqn="$4"
  local existing_action_id="$5"

  assert_not_equal "$existing_action_id" ""

  run action_plan_target_status "$output_file" "$action_name" "$namespace_fqn"
  assert_success
  assert_equal "$output" "already_migrated"

  local effective_target_id
  effective_target_id=$(action_plan_target_effective_id "$output_file" "$action_name" "$namespace_fqn")
  assert_not_equal "$effective_target_id" ""
  assert_equal "$effective_target_id" "$existing_action_id"

  local existing_action_json
  existing_action_json=$(./otdfctl $HOST $WITH_CREDS policy actions get --id "$existing_action_id" --json)

  assert_equal "$(echo "$existing_action_json" | jq -r '.id // empty')" "$existing_action_id"
  assert_equal "$(echo "$existing_action_json" | jq -r '.namespace.id')" "$namespace_id"
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

  local source_action_json
  source_action_json=$(./otdfctl $HOST $WITH_CREDS policy actions get --id "$source_action_id" --json)

  local created_action_json
  created_action_json=$(./otdfctl $HOST $WITH_CREDS policy actions get --id "$created_target_id" --json)

  assert_equal "$(echo "$created_action_json" | jq -r '.id')" "$created_target_id"
  assert_equal "$(echo "$created_action_json" | jq -r '.name')" "$action_name"
  assert_equal "$(echo "$created_action_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_metadata_labels_preserved "$source_action_json" "$created_action_json"
  assert_equal "$(echo "$created_action_json" | jq -r '.metadata.labels.migrated_from')" "$source_action_id"
  assert_not_equal "$(echo "$created_action_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_legacy_custom_action_still_exists() {
  local action_id="$1"
  local action_name="$2"

  assert_not_equal "$action_id" ""
  assert_not_equal "$action_name" ""

  local legacy_action_json
  legacy_action_json=$(./otdfctl $HOST $WITH_CREDS policy actions get --id "$action_id" --json)

  assert_equal "$(echo "$legacy_action_json" | jq -r '.id // empty')" "$action_id"
  assert_equal "$(echo "$legacy_action_json" | jq -r '.name')" "$action_name"
  assert_equal "$(echo "$legacy_action_json" | jq -r '.namespace.id // empty')" ""
}

assert_scs_created_in_namespace() {
  local output_file="$1"
  local source_scs_id="$2"
  local namespace_id="$3"
  local namespace_fqn="$4"

  run scs_plan_target_status "$output_file" "$source_scs_id" "$namespace_fqn"
  assert_success
  assert_equal "$output" "create"

  local created_target_id
  created_target_id=$(scs_plan_target_effective_id "$output_file" "$source_scs_id" "$namespace_fqn")
  assert_not_equal "$created_target_id" ""

  local source_scs_json
  source_scs_json=$(./otdfctl $HOST $WITH_CREDS policy scs get --id "$source_scs_id" --json)

  local created_scs_json
  created_scs_json=$(./otdfctl $HOST $WITH_CREDS policy scs get --id "$created_target_id" --json)

  assert_equal "$(echo "$created_scs_json" | jq -r '.id')" "$created_target_id"
  assert_equal "$(echo "$created_scs_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$created_scs_json" | jq -c '.subject_sets')" "$(echo "$source_scs_json" | jq -c '.subject_sets')"
  assert_metadata_labels_preserved "$source_scs_json" "$created_scs_json"
  assert_equal "$(echo "$created_scs_json" | jq -r '.metadata.labels.migrated_from')" "$source_scs_id"
  assert_not_equal "$(echo "$created_scs_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_scs_already_migrated_in_namespace() {
  local output_file="$1"
  local source_scs_id="$2"
  local namespace_id="$3"
  local namespace_fqn="$4"
  local existing_scs_id="$5"

  assert_not_equal "$existing_scs_id" ""

  run scs_plan_target_status "$output_file" "$source_scs_id" "$namespace_fqn"
  assert_success
  assert_equal "$output" "already_migrated"

  local effective_target_id
  effective_target_id=$(scs_plan_target_effective_id "$output_file" "$source_scs_id" "$namespace_fqn")
  assert_not_equal "$effective_target_id" ""
  assert_equal "$effective_target_id" "$existing_scs_id"

  local source_scs_json
  source_scs_json=$(./otdfctl $HOST $WITH_CREDS policy scs get --id "$source_scs_id" --json)

  local existing_scs_json
  existing_scs_json=$(./otdfctl $HOST $WITH_CREDS policy scs get --id "$existing_scs_id" --json)

  assert_equal "$(echo "$existing_scs_json" | jq -r '.id // empty')" "$existing_scs_id"
  assert_equal "$(echo "$existing_scs_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$existing_scs_json" | jq -c '.subject_sets')" "$(echo "$source_scs_json" | jq -c '.subject_sets')"
}

assert_legacy_scs_still_exists() {
  local source_scs_id="$1"

  assert_not_equal "$source_scs_id" ""

  local legacy_scs_json
  legacy_scs_json=$(./otdfctl $HOST $WITH_CREDS policy scs get --id "$source_scs_id" --json)

  assert_equal "$(echo "$legacy_scs_json" | jq -r '.id // empty')" "$source_scs_id"
  assert_equal "$(echo "$legacy_scs_json" | jq -r '.namespace.id // empty')" ""
}

run_namespaced_policy_commit() {
  local scope="$1"
  local output_file="$2"

  run_otdfctl_migrate --commit namespaced-policy --scope "$scope" --output "$output_file"
}

setup() {
  export TEST_PREFIX="${MIGRATION_TEST_PREFIX}-t${BATS_TEST_NUMBER}"
  export TRACKED_ACTION_IDS=""
  export TRACKED_SCS_IDS=""
  export TRACKED_SUBJECT_MAPPING_IDS=""
}

setup_file() {
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  export MIGRATION_TEST_PREFIX="np-migrate-$(date +%s)"
  export MIGRATION_OUTPUT_DIR="/tmp/${MIGRATION_TEST_PREFIX}"
  mkdir -p "$MIGRATION_OUTPUT_DIR"

  export NS_A_NAME="${MIGRATION_TEST_PREFIX}-a.test"
  export NS_B_NAME="${MIGRATION_TEST_PREFIX}-b.test"
  export NS_A_FQN="https://${NS_A_NAME}"
  export NS_B_FQN="https://${NS_B_NAME}"

  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name \"$NS_A_NAME\" --json"
  assert_success
  export NS_A_ID
  NS_A_ID=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$NS_A_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes namespaces create --name \"$NS_B_NAME\" --json"
  assert_success
  export NS_B_ID
  NS_B_ID=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$NS_B_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes create --name \"${MIGRATION_TEST_PREFIX}-attr-a\" --namespace \"$NS_A_ID\" --rule ANY_OF -v \"${MIGRATION_TEST_PREFIX}-a1\" --json"
  assert_success
  attr_a_json="$output"
  export ATTR_A_ID ATTR_A_VAL_1_ID
  ATTR_A_ID=$(echo "$attr_a_json" | jq -r '.id // empty')
  ATTR_A_VAL_1_ID=$(echo "$attr_a_json" | jq -r '.values[0].id // empty')
  assert_not_equal "$ATTR_A_ID" ""
  assert_not_equal "$ATTR_A_VAL_1_ID" ""

  # ATTR_A values resolve under the namespace FQN:
  #   ${NS_A_FQN}/attr/${MIGRATION_TEST_PREFIX}-attr-a/value/${MIGRATION_TEST_PREFIX}-a1
  #   ${NS_A_FQN}/attr/${MIGRATION_TEST_PREFIX}-attr-a/value/${MIGRATION_TEST_PREFIX}-a2
  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes values create --attribute-id \"$ATTR_A_ID\" --value \"${MIGRATION_TEST_PREFIX}-a2\" --json"
  assert_success
  export ATTR_A_VAL_2_ID
  ATTR_A_VAL_2_ID=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$ATTR_A_VAL_2_ID" ""

  # ATTR_B values resolve under the namespace FQN:
  #   ${NS_B_FQN}/attr/${MIGRATION_TEST_PREFIX}-attr-b/value/${MIGRATION_TEST_PREFIX}-b1
  run sh -c "./otdfctl $HOST $WITH_CREDS policy attributes create --name \"${MIGRATION_TEST_PREFIX}-attr-b\" --namespace \"$NS_B_ID\" --rule ANY_OF -v \"${MIGRATION_TEST_PREFIX}-b1\" --json"
  assert_success
  attr_b_json="$output"
  export ATTR_B_ID ATTR_B_VAL_1_ID
  ATTR_B_ID=$(echo "$attr_b_json" | jq -r '.id // empty')
  ATTR_B_VAL_1_ID=$(echo "$attr_b_json" | jq -r '.values[0].id // empty')
  assert_not_equal "$ATTR_B_ID" ""
  assert_not_equal "$ATTR_B_VAL_1_ID" ""

  run sh -c "./otdfctl $HOST $WITH_CREDS policy actions get --name read --json"
  assert_success
  export GLOBAL_READ_ID
  GLOBAL_READ_ID=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$GLOBAL_READ_ID" ""
}

teardown() {
  local subject_mapping_id
  local delete_output
  local delete_status
  while IFS= read -r subject_mapping_id; do
    [ -n "$subject_mapping_id" ] || continue
    if delete_output=$(./otdfctl $HOST $WITH_CREDS policy subject-mappings delete --id "$subject_mapping_id" --force 2>&1); then
      :
    else
      delete_status=$?
      echo "warning: failed to delete subject mapping fixture $subject_mapping_id during teardown (exit $delete_status): $delete_output" >&2
    fi
  done <<< "$TRACKED_SUBJECT_MAPPING_IDS"

  local scs_id
  while IFS= read -r scs_id; do
    [ -n "$scs_id" ] || continue
    if delete_output=$(./otdfctl $HOST $WITH_CREDS policy scs delete --id "$scs_id" --force 2>&1); then
      :
    else
      delete_status=$?
      echo "warning: failed to delete subject condition set fixture $scs_id during teardown (exit $delete_status): $delete_output" >&2
    fi
  done <<< "$TRACKED_SCS_IDS"

  local action_id
  while IFS= read -r action_id; do
    [ -n "$action_id" ] || continue
    if delete_output=$(./otdfctl $HOST $WITH_CREDS policy actions delete --id "$action_id" --force 2>&1); then
      :
    else
      delete_status=$?
      echo "warning: failed to delete action fixture $action_id during teardown (exit $delete_status): $delete_output" >&2
    fi
  done <<< "$TRACKED_ACTION_IDS"
}

teardown_file() {
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_A_ID" --force
  ./otdfctl $HOST $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_B_ID" --force

  rm -rf "$MIGRATION_OUTPUT_DIR"

  unset HOST WITH_CREDS MIGRATION_TEST_PREFIX MIGRATION_OUTPUT_DIR TEST_PREFIX
  unset NS_A_NAME NS_B_NAME NS_A_FQN NS_B_FQN NS_A_ID NS_B_ID
  unset ATTR_A_ID ATTR_A_VAL_1_ID ATTR_A_VAL_2_ID ATTR_B_ID ATTR_B_VAL_1_ID
  unset GLOBAL_READ_ID
  unset TRACKED_ACTION_IDS TRACKED_SCS_IDS TRACKED_SUBJECT_MAPPING_IDS
}

# Asserts action-scope migration resolves shared standard actions in-place,
# creates only the required custom action target, preserves metadata, does not
# create namespaced subject mappings as a side effect, and is idempotent on
# rerun.
@test "migrate namespaced-policy actions resolves standard actions and creates custom actions" {
  local custom_action_name="${TEST_PREFIX}-download"
  local shared_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-engineering"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local custom_action_labels=(--label "test_case=actions" --label "fixture=${TEST_PREFIX}-custom-action")
  local custom_action_id
  local shared_scs_id

  create_global_action custom_action_id "$custom_action_name" "${custom_action_labels[@]}"
  create_global_scs shared_scs_id "$shared_scs"

  # These anchor subject mappings stay legacy/global. Their target namespace
  # should be derived from the referenced attribute value during migration.
  local ignored_mapping_id
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_A_VAL_1_ID" "$GLOBAL_READ_ID" "$shared_scs_id"
  # TODO(DSPX-2717): Replace the custom-action namespace anchor with a
  # registered-resource or obligation-trigger fixture once those scope tests
  # land, so action-scope coverage is not driven entirely by subject mappings.
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_A_VAL_2_ID" "$custom_action_id" "$shared_scs_id"
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$shared_scs_id"

  local output_file="${MIGRATION_OUTPUT_DIR}/actions-plan.json"

  run_namespaced_policy_commit "actions" "$output_file"
  assert_success

  assert_action_target_count "$output_file" "read" 2
  assert_standard_action_resolved_in_namespace "$output_file" "read" "$NS_A_ID" "$NS_A_FQN"
  assert_standard_action_resolved_in_namespace "$output_file" "read" "$NS_B_ID" "$NS_B_FQN"

  assert_action_target_count "$output_file" "$custom_action_name" 1
  source_action_id=$(action_plan_source_id "$output_file" "$custom_action_name")
  assert_equal "$source_action_id" "$custom_action_id"
  assert_custom_action_created_in_namespace "$output_file" "$custom_action_name" "$custom_action_id" "$NS_A_ID" "$NS_A_FQN"
  assert_action_target_absent "$output_file" "$custom_action_name" "$NS_B_FQN"

  assert_legacy_custom_action_still_exists "$custom_action_id" "$custom_action_name"
  assert_no_subject_mappings_in_namespace "$NS_A_ID"
  assert_no_subject_mappings_in_namespace "$NS_B_ID"

  # Re-running the same migration should be idempotent. Custom action targets
  # should now be marked already_migrated, while standard actions still resolve
  # as existing_standard.
  local rerun_output_file="${MIGRATION_OUTPUT_DIR}/actions-rerun-plan.json"
  local custom_action_target_id
  # Get the created ids of the objects from the initial run's output file.
  custom_action_target_id=$(action_plan_target_effective_id "$output_file" "$custom_action_name" "$NS_A_FQN")

  run_namespaced_policy_commit "actions" "$rerun_output_file"
  assert_success

  assert_action_target_count "$rerun_output_file" "read" 2
  assert_standard_action_resolved_in_namespace "$rerun_output_file" "read" "$NS_A_ID" "$NS_A_FQN"
  assert_standard_action_resolved_in_namespace "$rerun_output_file" "read" "$NS_B_ID" "$NS_B_FQN"
  assert_action_target_count "$rerun_output_file" "$custom_action_name" 1
  assert_action_already_migrated_in_namespace "$rerun_output_file" "$custom_action_name" "$NS_A_ID" "$NS_A_FQN" "$custom_action_target_id"
  assert_action_target_absent "$rerun_output_file" "$custom_action_name" "$NS_B_FQN"
  assert_no_subject_mappings_in_namespace "$NS_A_ID"
  assert_no_subject_mappings_in_namespace "$NS_B_ID"
}

# Asserts SCS-scope migration creates missing namespaced SCS targets, reuses an
# already-migrated canonical target when present, preserves subject_sets and
# metadata, does not create namespaced subject mappings as a side effect, and
# is idempotent on rerun.
@test "migrate namespaced-policy subject-condition-sets creates single-namespace targets and reuses existing fanout targets" {
  local fanout_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-shared"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local single_namespace_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-a-only"],"subject_external_selector_value":".team.name"}],"boolean_operator":1}]}]'
  local fanout_scs_labels=(--label "test_case=scs" --label "fixture=${TEST_PREFIX}-fanout-scs")
  local single_namespace_scs_labels=(--label "test_case=scs" --label "fixture=${TEST_PREFIX}-single-scs")
  local fanout_scs_id
  local single_namespace_scs_id
  local existing_fanout_ns_b_scs_id

  create_global_scs fanout_scs_id "$fanout_scs" "${fanout_scs_labels[@]}"
  create_global_scs single_namespace_scs_id "$single_namespace_scs" "${single_namespace_scs_labels[@]}"
  create_namespaced_scs existing_fanout_ns_b_scs_id "$NS_B_ID" "$fanout_scs"

  local ignored_mapping_id
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_A_VAL_1_ID" "$GLOBAL_READ_ID" "$fanout_scs_id"
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$fanout_scs_id"
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_A_VAL_2_ID" "$GLOBAL_READ_ID" "$single_namespace_scs_id"

  local output_file="${MIGRATION_OUTPUT_DIR}/subject-condition-sets-plan.json"

  run_namespaced_policy_commit "subject-condition-sets" "$output_file"
  assert_success

  assert_scs_target_count "$output_file" "$fanout_scs_id" 2
  assert_scs_created_in_namespace "$output_file" "$fanout_scs_id" "$NS_A_ID" "$NS_A_FQN"
  assert_scs_already_migrated_in_namespace "$output_file" "$fanout_scs_id" "$NS_B_ID" "$NS_B_FQN" "$existing_fanout_ns_b_scs_id"

  assert_scs_target_count "$output_file" "$single_namespace_scs_id" 1
  assert_scs_created_in_namespace "$output_file" "$single_namespace_scs_id" "$NS_A_ID" "$NS_A_FQN"
  assert_scs_target_absent "$output_file" "$single_namespace_scs_id" "$NS_B_FQN"

  assert_legacy_scs_still_exists "$fanout_scs_id"
  assert_legacy_scs_still_exists "$single_namespace_scs_id"
  assert_no_subject_mappings_in_namespace "$NS_A_ID"
  assert_no_subject_mappings_in_namespace "$NS_B_ID"

  # Re-running the same migration should be idempotent. The previously created
  # SCS targets should now be marked already_migrated, and the pre-existing
  # canonical target should continue to resolve as already_migrated.
  local rerun_output_file="${MIGRATION_OUTPUT_DIR}/subject-condition-sets-rerun-plan.json"
  local fanout_ns_a_target_id
  local single_namespace_target_id
  # Get the created ids of the objects from the initial run's output file.
  fanout_ns_a_target_id=$(scs_plan_target_effective_id "$output_file" "$fanout_scs_id" "$NS_A_FQN")
  single_namespace_target_id=$(scs_plan_target_effective_id "$output_file" "$single_namespace_scs_id" "$NS_A_FQN")

  run_namespaced_policy_commit "subject-condition-sets" "$rerun_output_file"
  assert_success

  assert_scs_target_count "$rerun_output_file" "$fanout_scs_id" 2
  assert_scs_already_migrated_in_namespace "$rerun_output_file" "$fanout_scs_id" "$NS_A_ID" "$NS_A_FQN" "$fanout_ns_a_target_id"
  assert_scs_already_migrated_in_namespace "$rerun_output_file" "$fanout_scs_id" "$NS_B_ID" "$NS_B_FQN" "$existing_fanout_ns_b_scs_id"
  assert_scs_target_count "$rerun_output_file" "$single_namespace_scs_id" 1
  assert_scs_already_migrated_in_namespace "$rerun_output_file" "$single_namespace_scs_id" "$NS_A_ID" "$NS_A_FQN" "$single_namespace_target_id"
  assert_scs_target_absent "$rerun_output_file" "$single_namespace_scs_id" "$NS_B_FQN"
  assert_no_subject_mappings_in_namespace "$NS_A_ID"
  assert_no_subject_mappings_in_namespace "$NS_B_ID"
}

# Asserts subject-mapping migration creates namespaced mappings, rewrites action
# and SCS dependencies to the correct target IDs, preserves source metadata on
# the migrated subject mappings, and is idempotent on rerun.
@test "migrate namespaced-policy subject-mappings rewrites action and scs dependencies" {
  local custom_action_name="${TEST_PREFIX}-download"
  local sm_a_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-sm-a"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local sm_b_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-sm-b"],"subject_external_selector_value":".team.name"}],"boolean_operator":1}]}]'
  local custom_action_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-custom-action")
  local sm_a_scs_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-sm-a-scs")
  local sm_b_scs_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-sm-b-scs")
  local mapping_a_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-mapping-a")
  local mapping_b_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-mapping-b")
  local custom_action_id
  local sm_a_scs_id
  local sm_b_scs_id
  local mapping_a_id
  local mapping_b_id

  create_global_action custom_action_id "$custom_action_name" "${custom_action_labels[@]}"
  create_global_scs sm_a_scs_id "$sm_a_scs" "${sm_a_scs_labels[@]}"
  create_global_scs sm_b_scs_id "$sm_b_scs" "${sm_b_scs_labels[@]}"

  create_legacy_subject_mapping mapping_a_id "$ATTR_A_VAL_1_ID" "$custom_action_id" "$sm_a_scs_id" "${mapping_a_labels[@]}"
  create_legacy_subject_mapping mapping_b_id "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$sm_b_scs_id" "${mapping_b_labels[@]}"

  local output_file="${MIGRATION_OUTPUT_DIR}/subject-mappings-plan.json"

  run_namespaced_policy_commit "subject-mappings" "$output_file"
  assert_success

  assert_subject_mapping_target_count "$output_file" "$mapping_a_id" 1
  assert_subject_mapping_created_in_namespace "$output_file" "$mapping_a_id" "$NS_A_ID" "$NS_A_FQN" "$ATTR_A_VAL_1_ID" "$custom_action_name" "$custom_action_id" "create" 1 "$sm_a_scs_id" 1

  assert_subject_mapping_target_count "$output_file" "$mapping_b_id" 1
  assert_subject_mapping_created_in_namespace "$output_file" "$mapping_b_id" "$NS_B_ID" "$NS_B_FQN" "$ATTR_B_VAL_1_ID" "read" "$GLOBAL_READ_ID" "existing_standard" 1 "$sm_b_scs_id" 1

  assert_legacy_subject_mapping_still_exists "$ATTR_A_VAL_1_ID" "$mapping_a_id"
  assert_legacy_subject_mapping_still_exists "$ATTR_B_VAL_1_ID" "$mapping_b_id"

  # Re-running the same migration should be idempotent. The custom action,
  # migrated SCS targets, and migrated subject mappings should all resolve as
  # already_migrated on the second pass. Standard read remains existing_standard.
  local rerun_output_file="${MIGRATION_OUTPUT_DIR}/subject-mappings-rerun-plan.json"
  local custom_action_target_id
  local sm_a_scs_target_id
  local sm_b_scs_target_id
  local mapping_a_target_id
  local mapping_b_target_id
  # Get the created ids of the objects from the initial run's output file.
  custom_action_target_id=$(action_plan_target_effective_id "$output_file" "$custom_action_name" "$NS_A_FQN")
  sm_a_scs_target_id=$(scs_plan_target_effective_id "$output_file" "$sm_a_scs_id" "$NS_A_FQN")
  sm_b_scs_target_id=$(scs_plan_target_effective_id "$output_file" "$sm_b_scs_id" "$NS_B_FQN")
  mapping_a_target_id=$(subject_mapping_plan_target_effective_id "$output_file" "$mapping_a_id" "$NS_A_FQN")
  mapping_b_target_id=$(subject_mapping_plan_target_effective_id "$output_file" "$mapping_b_id" "$NS_B_FQN")

  run_namespaced_policy_commit "subject-mappings" "$rerun_output_file"
  assert_success

  assert_action_target_count "$rerun_output_file" "$custom_action_name" 1
  assert_action_already_migrated_in_namespace "$rerun_output_file" "$custom_action_name" "$NS_A_ID" "$NS_A_FQN" "$custom_action_target_id"
  assert_action_target_count "$rerun_output_file" "read" 1
  assert_standard_action_resolved_in_namespace "$rerun_output_file" "read" "$NS_B_ID" "$NS_B_FQN"
  assert_scs_target_count "$rerun_output_file" "$sm_a_scs_id" 1
  assert_scs_already_migrated_in_namespace "$rerun_output_file" "$sm_a_scs_id" "$NS_A_ID" "$NS_A_FQN" "$sm_a_scs_target_id"
  assert_scs_target_count "$rerun_output_file" "$sm_b_scs_id" 1
  assert_scs_already_migrated_in_namespace "$rerun_output_file" "$sm_b_scs_id" "$NS_B_ID" "$NS_B_FQN" "$sm_b_scs_target_id"
  assert_subject_mapping_target_count "$rerun_output_file" "$mapping_a_id" 1
  assert_subject_mapping_already_migrated_in_namespace "$rerun_output_file" "$mapping_a_id" "$NS_A_ID" "$NS_A_FQN" "$mapping_a_target_id"
  assert_subject_mapping_target_count "$rerun_output_file" "$mapping_b_id" 1
  assert_subject_mapping_already_migrated_in_namespace "$rerun_output_file" "$mapping_b_id" "$NS_B_ID" "$NS_B_FQN" "$mapping_b_target_id"
}
