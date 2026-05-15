#!/usr/bin/env bats

# bats file_tags=namespaced_policy_migration

# Tests for namespaced-policy migration
# This file needs isolated execution while the rest of otdfctl/e2e is still
# running in parallel. The migration planner discovers legacy/global policy
# objects by scope, so overlapping unnamespaced fixtures from other BATS files
# can pollute these migration assertions.
# CI should run this tag in a separate invocation, then run the remaining suite
# with this tag filtered out.
#
# Paths intentionally covered here:
# - action-scope migration creates only namespaced action targets, including
#   custom-action fanout across namespaces from RR and trigger anchors
# - standard read action resolves to the canonical namespaced target where
#   downstream migrations depend on it
# - SCS migration handles single-namespace placement, cross-namespace fanout,
#   and reuse of an already-existing canonical target
# - subject-mapping migration rewrites action and SCS dependencies correctly
#   and can reuse an already-existing canonical target
# - registered-resource migration rewrites action bindings and reuses canonical
#   targets when they already exist
# - obligation-trigger migration rewrites action dependencies and reuses
#   canonical targets when they already exist
# - combined all-scope migration creates one target per supported object type
# - every covered scope verifies idempotent reruns and that legacy source
#   objects remain in place after migration
#
# Paths that are not in these e2e tests:
# - planner-only or dry-run output, summary formatting, and status bucket
#   assertions such as create/already_migrated/existing_standard/unresolved
# - unresolved or interactive-review flows, especially conflicting registered
#   resources and manual namespace selection
# - unused legacy objects being skipped entirely by planning and execution
# - subject mappings with multiple actions
# - RRs with multiple action-attribute values

run_otdfctl_migrate() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json migrate "$@"
  assert_success
}

run_otdfctl_action() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy actions "$@"
  assert_success
}

run_otdfctl_sm() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy subject-mappings "$@"
  assert_success
}

run_otdfctl_scs() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy scs "$@"
  assert_success
}

run_otdfctl_registered_resources() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy registered-resources "$@"
  assert_success
}

run_otdfctl_registered_resource_values() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy registered-resources values "$@"
  assert_success
}

run_otdfctl_obligations() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy obligations "$@"
  assert_success
}

run_otdfctl_obligation_values() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy obligations values "$@"
  assert_success
}

run_otdfctl_obligation_triggers() {
  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy obligations triggers "$@"
  assert_success
}

sql_escape_literal() {
  printf "%s" "$1" | sed "s/'/''/g"
}

run_policy_db_sql() {
  local sql="$1"

  run env \
    PGPASSWORD="${OPENTDF_DB_PASSWORD:-changeme}" \
    psql \
    -h "${OPENTDF_DB_HOST:-localhost}" \
    -p "${OPENTDF_DB_PORT:-5432}" \
    -U "${OPENTDF_DB_USER:-postgres}" \
    -d "${OPENTDF_DB_DATABASE:-opentdf}" \
    -X \
    -v ON_ERROR_STOP=1 \
    -Atqc "SET search_path TO \"opentdf_policy\", public; ${sql}"
}

build_metadata_json_from_labels() {
  if [ "$#" -eq 0 ]; then
    printf '{}'
    return
  fi

  local metadata_json='{"labels":{}}'
  local label
  local key
  local value

  for label in "$@"; do
    key="${label%%=*}"
    if [ "$key" = "$label" ]; then
      value=""
    else
      value="${label#*=}"
    fi

    metadata_json=$(jq -c --arg key "$key" --arg value "$value" '.labels[$key] = $value' <<< "$metadata_json")
  done

  printf '%s' "$metadata_json"
}

track_action_id() {
  local action_id="$1"
  TRACKED_ACTION_IDS="${TRACKED_ACTION_IDS}${action_id}"$'\n'
}

track_registered_resource_id() {
  local resource_id="$1"
  TRACKED_REGISTERED_RESOURCE_IDS="${TRACKED_REGISTERED_RESOURCE_IDS}${resource_id}"$'\n'
}

track_registered_resource_value_id() {
  local resource_value_id="$1"
  TRACKED_REGISTERED_RESOURCE_VALUE_IDS="${TRACKED_REGISTERED_RESOURCE_VALUE_IDS}${resource_value_id}"$'\n'
}

track_scs_id() {
  local scs_id="$1"
  TRACKED_SCS_IDS="${TRACKED_SCS_IDS}${scs_id}"$'\n'
}

track_subject_mapping_id() {
  local subject_mapping_id="$1"
  TRACKED_SUBJECT_MAPPING_IDS="${TRACKED_SUBJECT_MAPPING_IDS}${subject_mapping_id}"$'\n'
}

track_obligation_trigger_id() {
  local obligation_trigger_id="$1"
  TRACKED_OBLIGATION_TRIGGER_IDS="${TRACKED_OBLIGATION_TRIGGER_IDS}${obligation_trigger_id}"$'\n'
}

create_global_action() {
  local result_var="$1"
  local action_name="$2"
  shift 2

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy actions create --name "$action_name" "$@" --json
  assert_success

  local created_action_id
  created_action_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_action_id" ""

  track_action_id "$created_action_id"
  printf -v "$result_var" '%s' "$created_action_id"
}

create_global_scs() {
  local result_var="$1"
  local subject_sets_json="$2"
  shift 2

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy scs create --subject-sets "$subject_sets_json" "$@" --json
  assert_success

  local created_scs_id
  created_scs_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_scs_id" ""

  track_scs_id "$created_scs_id"
  printf -v "$result_var" '%s' "$created_scs_id"
}

create_namespaced_scs() {
  local result_var="$1"
  local namespace_id="$2"
  local subject_sets_json="$3"
  shift 3

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy scs create --namespace "$namespace_id" --subject-sets "$subject_sets_json" "$@" --json
  assert_success

  local created_scs_id
  created_scs_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_scs_id" ""

  track_scs_id "$created_scs_id"
  printf -v "$result_var" '%s' "$created_scs_id"
}

create_legacy_subject_mapping() {
  local result_var="$1"
  local attribute_value_id="$2"
  local action_id="$3"
  local subject_condition_set_id="$4"
  shift 4

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy subject-mappings create --attribute-value-id "$attribute_value_id" --action "$action_id" --subject-condition-set-id "$subject_condition_set_id" "$@" --json
  assert_success

  local created_subject_mapping_id
  created_subject_mapping_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_subject_mapping_id" ""

  track_subject_mapping_id "$created_subject_mapping_id"
  printf -v "$result_var" '%s' "$created_subject_mapping_id"
}

create_namespaced_subject_mapping() {
  local result_var="$1"
  local namespace_id="$2"
  local attribute_value_id="$3"
  local action_id="$4"
  local subject_condition_set_id="$5"
  shift 5

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy subject-mappings create --namespace "$namespace_id" --attribute-value-id "$attribute_value_id" --action "$action_id" --subject-condition-set-id "$subject_condition_set_id" "$@" --json
  assert_success

  local created_subject_mapping_id
  created_subject_mapping_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_subject_mapping_id" ""

  track_subject_mapping_id "$created_subject_mapping_id"
  printf -v "$result_var" '%s' "$created_subject_mapping_id"
}

create_global_registered_resource() {
  local result_var="$1"
  local resource_name="$2"
  shift 2

  run_otdfctl_registered_resources create --name "$resource_name" "$@" --json
  assert_success

  local created_resource_id
  created_resource_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_resource_id" ""

  track_registered_resource_id "$created_resource_id"
  printf -v "$result_var" '%s' "$created_resource_id"
}

create_registered_resource_value() {
  local result_var="$1"
  local resource_id="$2"
  local resource_value="$3"
  shift 3

  run_otdfctl_registered_resource_values create --resource "$resource_id" --value "$resource_value" "$@" --json
  assert_success

  local created_resource_value_id
  created_resource_value_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_resource_value_id" ""

  track_registered_resource_value_id "$created_resource_value_id"
  printf -v "$result_var" '%s' "$created_resource_value_id"
}

create_namespaced_obligation() {
  local result_var="$1"
  local namespace_id="$2"
  local obligation_name="$3"
  shift 3

  run_otdfctl_obligations create --namespace "$namespace_id" --name "$obligation_name" "$@" --json
  assert_success

  local created_obligation_id
  created_obligation_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_obligation_id" ""

  printf -v "$result_var" '%s' "$created_obligation_id"
}

create_obligation_value() {
  local result_var="$1"
  local obligation_id="$2"
  local obligation_value="$3"
  shift 3

  run_otdfctl_obligation_values create --obligation "$obligation_id" --value "$obligation_value" "$@" --json
  assert_success

  local created_obligation_value_id
  created_obligation_value_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$created_obligation_value_id" ""

  printf -v "$result_var" '%s' "$created_obligation_value_id"
}

create_legacy_obligation_trigger() {
  local result_var="$1"
  local attribute_value_id="$2"
  local action_id="$3"
  local obligation_value_id="$4"
  shift 4

  local client_id=""
  local labels=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --client-id)
        client_id="$2"
        shift 2
        ;;
      --label)
        labels+=("$2")
        shift 2
        ;;
      *)
        echo "unsupported create_legacy_obligation_trigger arg: $1" >&2
        return 1
        ;;
    esac
  done

  local metadata_json
  metadata_json=$(build_metadata_json_from_labels "${labels[@]}")

  local client_id_sql="NULL"
  if [ -n "$client_id" ]; then
    client_id_sql="'$(sql_escape_literal "$client_id")'"
  fi

  # The API now rejects action/obligation namespace mismatches, but this test
  # needs a legacy/global action bound to a namespaced obligation. Seed the row
  # directly to exercise the migration flow against persisted legacy data.
  run_policy_db_sql "
    INSERT INTO obligation_triggers (
      obligation_value_id,
      action_id,
      attribute_value_id,
      metadata,
      client_id
    )
    VALUES (
      '$(sql_escape_literal "$obligation_value_id")'::uuid,
      '$(sql_escape_literal "$action_id")'::uuid,
      '$(sql_escape_literal "$attribute_value_id")'::uuid,
      '$(sql_escape_literal "$metadata_json")'::jsonb,
      ${client_id_sql}
    )
    RETURNING id;
  "
  assert_success

  local created_obligation_trigger_id
  created_obligation_trigger_id=$(echo "$output" | tail -n 1)
  assert_not_equal "$created_obligation_trigger_id" ""

  track_obligation_trigger_id "$created_obligation_trigger_id"
  printf -v "$result_var" '%s' "$created_obligation_trigger_id"
}

lookup_namespaced_action_id() {
  local result_var="$1"
  local action_name="$2"
  local namespace_id="$3"

  local looked_up_action_json
  run_otdfctl_action get --name "$action_name" --namespace "$namespace_id" --json
  looked_up_action_json="$output"

  local looked_up_action_id
  looked_up_action_id=$(echo "$looked_up_action_json" | jq -r '.id // empty')
  assert_not_equal "$looked_up_action_id" ""

  printf -v "$result_var" '%s' "$looked_up_action_id"
}

namespace_state_json() {
  local namespace_filter="$1"
  local actions_total
  local subject_mappings_total
  local scs_total
  local registered_resources_total
  local obligation_triggers_total
  local actions_json
  local subject_mappings_json
  local scs_json
  local registered_resources_json
  local obligation_triggers_json

  run_otdfctl_action list --namespace "$namespace_filter" --limit 1 --offset 0 --json
  actions_json="$output"
  actions_total=$(echo "$actions_json" | jq -r '.pagination.total // 0')

  run_otdfctl_sm list --namespace "$namespace_filter" --limit 1 --offset 0 --json
  subject_mappings_json="$output"
  subject_mappings_total=$(echo "$subject_mappings_json" | jq -r '.pagination.total // 0')

  run_otdfctl_scs list --namespace "$namespace_filter" --limit 1 --offset 0 --json
  scs_json="$output"
  scs_total=$(echo "$scs_json" | jq -r '.pagination.total // 0')

  run_otdfctl_registered_resources list --namespace "$namespace_filter" --limit 1 --offset 0 --json
  registered_resources_json="$output"
  registered_resources_total=$(echo "$registered_resources_json" | jq -r '.pagination.total // 0')

  run_otdfctl_obligation_triggers list --namespace "$namespace_filter" --limit 1 --offset 0 --json
  obligation_triggers_json="$output"
  obligation_triggers_total=$(echo "$obligation_triggers_json" | jq -r '.pagination.total // 0')

  jq -cn \
    --argjson actions "$actions_total" \
    --argjson subject_mappings "$subject_mappings_total" \
    --argjson scs "$scs_total" \
    --argjson registered_resources "$registered_resources_total" \
    --argjson obligation_triggers "$obligation_triggers_total" \
    '{
      actions: $actions,
      subject_mappings: $subject_mappings,
      scs: $scs,
      registered_resources: $registered_resources,
      obligation_triggers: $obligation_triggers
    }'
}

assert_namespace_state_delta() {
  local before_state="$1"
  local after_state="$2"
  local expected_actions_delta="$3"
  local expected_subject_mappings_delta="$4"
  local expected_scs_delta="$5"
  local expected_registered_resources_delta="$6"
  local expected_obligation_triggers_delta="$7"
  local actual_delta_json
  local expected_delta_json

  actual_delta_json=$(
    jq -cn \
      --argjson before "$before_state" \
      --argjson after "$after_state" \
      '{
        actions: ($after.actions - $before.actions),
        subject_mappings: ($after.subject_mappings - $before.subject_mappings),
        scs: ($after.scs - $before.scs),
        registered_resources: ($after.registered_resources - $before.registered_resources),
        obligation_triggers: ($after.obligation_triggers - $before.obligation_triggers)
      }'
  )
  expected_delta_json=$(
    jq -cn \
      --argjson actions "$expected_actions_delta" \
      --argjson subject_mappings "$expected_subject_mappings_delta" \
      --argjson scs "$expected_scs_delta" \
      --argjson registered_resources "$expected_registered_resources_delta" \
      --argjson obligation_triggers "$expected_obligation_triggers_delta" \
      '{
        actions: $actions,
        subject_mappings: $subject_mappings,
        scs: $scs,
        registered_resources: $registered_resources,
        obligation_triggers: $obligation_triggers
      }'
  )

  assert_equal "$actual_delta_json" "$expected_delta_json"
}

subject_mapping_json_by_migrated_from() {
  local namespace_filter="$1"
  local source_mapping_id="$2"
  local subject_mappings_json

  run_otdfctl_sm list --namespace "$namespace_filter" --limit 100 --offset 0 --json
  subject_mappings_json="$output"

  echo "$subject_mappings_json" \
    | jq -cer --arg source_mapping_id "$source_mapping_id" '
      [
        (.subject_mappings // [])[]
        | select((.metadata.labels.migrated_from // "") == $source_mapping_id)
      ] | if length == 1 then .[0] else empty end
    '
}

subject_mapping_id_by_migrated_from() {
  local namespace_filter="$1"
  local source_mapping_id="$2"
  local migrated_mapping_id

  migrated_mapping_id=$(subject_mapping_json_by_migrated_from "$namespace_filter" "$source_mapping_id" | jq -r '.id // empty')
  assert_not_equal "$migrated_mapping_id" ""
  printf '%s\n' "$migrated_mapping_id"
}

assert_subject_mapping_created_in_namespace() {
  local source_mapping_id="$1"
  local namespace_id="$2"
  local attribute_value_id="$3"
  local action_name="$4"
  local source_action_id="$5"
  local expected_action_status="$6"
  local source_scs_id="$7"

  case "$expected_action_status" in
    create)
      assert_custom_action_created_in_namespace "$action_name" "$source_action_id" "$namespace_id"
      ;;
    existing_standard)
      assert_standard_action_resolved_in_namespace "$action_name" "$namespace_id"
      ;;
    *)
      false
      ;;
  esac

  assert_scs_created_in_namespace "$source_scs_id" "$namespace_id"

  local expected_action_target_id
  expected_action_target_id=$(action_id_by_name_in_namespace "$action_name" "$namespace_id")

  local expected_scs_target_id
  expected_scs_target_id=$(scs_id_by_migrated_from "$namespace_id" "$source_scs_id")

  local source_mapping_json
  run_otdfctl_sm get --id "$source_mapping_id" --json
  source_mapping_json="$output"

  local created_mapping_json
  created_mapping_json=$(subject_mapping_json_by_migrated_from "$namespace_id" "$source_mapping_id")
  assert_not_equal "$created_mapping_json" ""

  local created_target_id
  created_target_id=$(echo "$created_mapping_json" | jq -r '.id // empty')
  assert_not_equal "$created_target_id" ""
  assert_not_equal "$created_target_id" "$source_mapping_id"

  assert_equal "$(echo "$created_mapping_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.attribute_value.id')" "$attribute_value_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.actions[0].id')" "$expected_action_target_id"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.subject_condition_set.id')" "$expected_scs_target_id"
  assert_metadata_labels_preserved "$source_mapping_json" "$created_mapping_json"
  assert_equal "$(echo "$created_mapping_json" | jq -r '.metadata.labels.migrated_from')" "$source_mapping_id"
  assert_not_equal "$(echo "$created_mapping_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_subject_mapping_already_migrated_in_namespace() {
  local source_mapping_id="$1"
  local namespace_id="$2"
  local existing_mapping_id="$3"

  assert_not_equal "$existing_mapping_id" ""

  local source_mapping_json
  run_otdfctl_sm get --id "$source_mapping_id" --json
  source_mapping_json="$output"

  local existing_mapping_json
  run_otdfctl_sm get --id "$existing_mapping_id" --json
  existing_mapping_json="$output"

  assert_equal "$(echo "$existing_mapping_json" | jq -r '.id // empty')" "$existing_mapping_id"
  assert_equal "$(echo "$existing_mapping_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$existing_mapping_json" | jq -r '.attribute_value.id')" "$(echo "$source_mapping_json" | jq -r '.attribute_value.id')"
}

assert_legacy_subject_mapping_still_exists() {
  local attribute_value_id="$1"
  local source_mapping_id="$2"

  assert_not_equal "$attribute_value_id" ""
  assert_not_equal "$source_mapping_id" ""

  local legacy_mapping_json
  run_otdfctl_sm get --id "$source_mapping_id" --json
  legacy_mapping_json="$output"

  assert_equal "$(echo "$legacy_mapping_json" | jq -r '.id // empty')" "$source_mapping_id"
  assert_equal "$(echo "$legacy_mapping_json" | jq -r '.namespace.id // empty')" ""
  assert_equal "$(echo "$legacy_mapping_json" | jq -r '.attribute_value.id')" "$attribute_value_id"
}

assert_no_subject_mappings_in_namespace() {
  local namespace_id="$1"
  local namespace_state

  namespace_state=$(namespace_state_json "$namespace_id")
  assert_equal "$(echo "$namespace_state" | jq -r '.subject_mappings')" "0"
}

obligation_trigger_json_by_id() {
  local trigger_id="$1"
  local namespace_filter="$2"
  local triggers_json

  run_otdfctl_obligation_triggers list --namespace "$namespace_filter" --limit 100 --offset 0 --json
  triggers_json="$output"

  echo "$triggers_json" \
    | jq -cer --arg trigger_id "$trigger_id" '(.triggers // [])[] | select(.id == $trigger_id)'
}

obligation_trigger_json_by_migrated_from() {
  local namespace_filter="$1"
  local source_trigger_id="$2"
  local triggers_json

  run_otdfctl_obligation_triggers list --namespace "$namespace_filter" --limit 100 --offset 0 --json
  triggers_json="$output"

  echo "$triggers_json" \
    | jq -cer --arg source_trigger_id "$source_trigger_id" '
      [
        (.triggers // [])[]
        | select((.metadata.labels.migrated_from // "") == $source_trigger_id)
      ] | if length == 1 then .[0] else empty end
    '
}

obligation_trigger_id_by_migrated_from() {
  local namespace_filter="$1"
  local source_trigger_id="$2"
  local migrated_trigger_id

  migrated_trigger_id=$(obligation_trigger_json_by_migrated_from "$namespace_filter" "$source_trigger_id" | jq -r '.id // empty')
  assert_not_equal "$migrated_trigger_id" ""
  printf '%s\n' "$migrated_trigger_id"
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

action_json_by_name_in_namespace() {
  local action_name="$1"
  local namespace_filter="$2"

  run_otdfctl_action get --name "$action_name" --namespace "$namespace_filter" --json
  printf '%s\n' "$output"
}

action_id_by_name_in_namespace() {
  local action_name="$1"
  local namespace_filter="$2"
  local action_id

  action_id=$(action_json_by_name_in_namespace "$action_name" "$namespace_filter" | jq -r '.id // empty')
  assert_not_equal "$action_id" ""
  printf '%s\n' "$action_id"
}

scs_json_by_migrated_from() {
  local namespace_filter="$1"
  local source_scs_id="$2"
  local scs_json

  run_otdfctl_scs list --namespace "$namespace_filter" --limit 100 --offset 0 --json
  scs_json="$output"

  echo "$scs_json" \
    | jq -cer --arg source_scs_id "$source_scs_id" '
      [
        (.subject_condition_sets // [])[]
        | select((.metadata.labels.migrated_from // "") == $source_scs_id)
      ] | if length == 1 then .[0] else empty end
    '
}

scs_id_by_migrated_from() {
  local namespace_filter="$1"
  local source_scs_id="$2"
  local migrated_scs_id

  migrated_scs_id=$(scs_json_by_migrated_from "$namespace_filter" "$source_scs_id" | jq -r '.id // empty')
  assert_not_equal "$migrated_scs_id" ""
  printf '%s\n' "$migrated_scs_id"
}

registered_resource_json_by_migrated_from() {
  local namespace_filter="$1"
  local source_resource_id="$2"
  local resources_json

  run_otdfctl_registered_resources list --namespace "$namespace_filter" --limit 100 --offset 0 --json
  resources_json="$output"

  echo "$resources_json" \
    | jq -cer --arg source_resource_id "$source_resource_id" '
      [
        (.resources // [])[]
        | select((.metadata.labels.migrated_from // "") == $source_resource_id)
      ] | if length == 1 then .[0] else empty end
    '
}

registered_resource_id_by_migrated_from() {
  local namespace_filter="$1"
  local source_resource_id="$2"
  local migrated_resource_id

  migrated_resource_id=$(registered_resource_json_by_migrated_from "$namespace_filter" "$source_resource_id" | jq -r '.id // empty')
  assert_not_equal "$migrated_resource_id" ""
  printf '%s\n' "$migrated_resource_id"
}

registered_resource_value_json_by_migrated_from() {
  local resource_id="$1"
  local source_value_id="$2"
  local resource_values_json

  run_otdfctl_registered_resource_values list --resource "$resource_id" --limit 100 --offset 0 --json
  resource_values_json="$output"

  echo "$resource_values_json" \
    | jq -cer --arg source_value_id "$source_value_id" '
      [
        (.values // [])[]
        | select((.metadata.labels.migrated_from // "") == $source_value_id)
      ] | if length == 1 then .[0] else empty end
    '
}

registered_resource_value_id_by_migrated_from() {
  local resource_id="$1"
  local source_value_id="$2"
  local migrated_resource_value_id

  migrated_resource_value_id=$(registered_resource_value_json_by_migrated_from "$resource_id" "$source_value_id" | jq -r '.id // empty')
  assert_not_equal "$migrated_resource_value_id" ""
  printf '%s\n' "$migrated_resource_value_id"
}

assert_action_absent_in_namespace() {
  local action_name="$1"
  local namespace_filter="$2"

  run ./otdfctl --host http://localhost:8080 --with-client-creds-file ./creds.json policy actions get --name "$action_name" --namespace "$namespace_filter" --json
  assert_failure
}

assert_scs_absent_in_namespace() {
  local source_scs_id="$1"
  local namespace_filter="$2"
  local scs_list_json

  run_otdfctl_scs list --namespace "$namespace_filter" --limit 100 --offset 0 --json
  scs_list_json="$output"
  assert_equal "$(echo "$scs_list_json" | jq -r --arg source_scs_id "$source_scs_id" '[(.subject_condition_sets // [])[] | select((.metadata.labels.migrated_from // "") == $source_scs_id)] | length')" "0"
}

registered_resource_values_signature() {
  local resource_json="$1"

  echo "$resource_json" | jq -c '
    def normalized_bindings:
      (.action_attribute_values // [])
      | map("\(.action.name | ascii_downcase)|\(.attribute_value.fqn)")
      | sort;

    (.values // [])
    | map({
        value: (.value | ascii_downcase),
        bindings: normalized_bindings
      })
    | sort_by([.value, (.bindings | join(","))])
  '
}

subject_sets_signature() {
  local scs_json="$1"

  echo "$scs_json" | jq -c '
    def normalized_condition:
      {
        selector: (.subject_external_selector_value // ""),
        operator: (.operator // 0),
        values: ((.subject_external_values // []) | sort)
      };

    def normalized_group:
      {
        conditions: (
          (.conditions // [])
          | map(select(. != null) | normalized_condition)
          | sort_by([.selector, .operator, (.values | join(","))])
        ),
        boolean_operator: (.boolean_operator // 0)
      };

    (.subject_sets // [])
    | map(
        select(. != null)
        | {
            condition_groups: (
              (.condition_groups // [])
              | map(select(. != null) | normalized_group)
              | sort_by(tojson)
            )
          }
      )
    | sort_by(tojson)
  '
}

assert_standard_action_resolved_in_namespace() {
  local action_name="$1"
  local namespace_id="$2"

  local live_action_json
  live_action_json=$(action_json_by_name_in_namespace "$action_name" "$namespace_id")
  assert_not_equal "$live_action_json" ""
  assert_not_equal "$(echo "$live_action_json" | jq -r '.id // empty')" ""
  assert_equal "$(echo "$live_action_json" | jq -r '.namespace.id')" "$namespace_id"
}

assert_action_already_migrated_in_namespace() {
  local action_name="$1"
  local namespace_id="$2"
  local existing_action_id="$3"

  local existing_action_json
  run_otdfctl_action get --id "$existing_action_id" --json
  existing_action_json="$output"

  assert_equal "$(echo "$existing_action_json" | jq -r '.id // empty')" "$existing_action_id"
  assert_equal "$(echo "$existing_action_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$existing_action_json" | jq -r '.name')" "$action_name"
}

assert_custom_action_created_in_namespace() {
  local action_name="$1"
  local source_action_id="$2"
  local namespace_id="$3"

  local source_action_json
  run_otdfctl_action get --id "$source_action_id" --json
  source_action_json="$output"

  local created_action_json
  created_action_json=$(action_json_by_name_in_namespace "$action_name" "$namespace_id")
  assert_not_equal "$created_action_json" ""

  local created_target_id
  created_target_id=$(echo "$created_action_json" | jq -r '.id // empty')
  assert_not_equal "$created_target_id" ""
  assert_not_equal "$created_target_id" "$source_action_id"

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
  run_otdfctl_action get --id "$action_id" --json
  legacy_action_json="$output"

  assert_equal "$(echo "$legacy_action_json" | jq -r '.id // empty')" "$action_id"
  assert_equal "$(echo "$legacy_action_json" | jq -r '.name')" "$action_name"
  assert_equal "$(echo "$legacy_action_json" | jq -r '.namespace.id // empty')" ""
}

assert_scs_created_in_namespace() {
  local source_scs_id="$1"
  local namespace_id="$2"

  local source_scs_json
  run_otdfctl_scs get --id "$source_scs_id" --json
  source_scs_json="$output"

  local created_scs_json
  created_scs_json=$(scs_json_by_migrated_from "$namespace_id" "$source_scs_id")
  assert_not_equal "$created_scs_json" ""

  local created_target_id
  created_target_id=$(echo "$created_scs_json" | jq -r '.id // empty')
  assert_not_equal "$created_target_id" ""
  assert_not_equal "$created_target_id" "$source_scs_id"

  assert_equal "$(echo "$created_scs_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(subject_sets_signature "$created_scs_json")" "$(subject_sets_signature "$source_scs_json")"
  assert_metadata_labels_preserved "$source_scs_json" "$created_scs_json"
  assert_equal "$(echo "$created_scs_json" | jq -r '.metadata.labels.migrated_from')" "$source_scs_id"
  assert_not_equal "$(echo "$created_scs_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_registered_resource_created_in_namespace() {
  local source_resource_id="$1"
  local source_value_id="$2"
  local namespace_id="$3"
  local resource_name="$4"
  local resource_value="$5"
  local action_name="$6"
  local source_action_id="$7"
  local expected_action_status="$8"
  local attribute_value_id="$9"

  case "$expected_action_status" in
    create)
      assert_custom_action_created_in_namespace "$action_name" "$source_action_id" "$namespace_id"
      ;;
    existing_standard)
      assert_standard_action_resolved_in_namespace "$action_name" "$namespace_id"
      ;;
    *)
      false
      ;;
  esac

  local expected_action_target_id
  expected_action_target_id=$(action_id_by_name_in_namespace "$action_name" "$namespace_id")

  local source_resource_json
  run_otdfctl_registered_resources get --id "$source_resource_id" --json
  source_resource_json="$output"

  local created_resource_json
  created_resource_json=$(registered_resource_json_by_migrated_from "$namespace_id" "$source_resource_id")
  assert_not_equal "$created_resource_json" ""

  local created_resource_id
  created_resource_id=$(echo "$created_resource_json" | jq -r '.id // empty')
  assert_not_equal "$created_resource_id" ""
  assert_not_equal "$created_resource_id" "$source_resource_id"

  assert_equal "$(echo "$created_resource_json" | jq -r '.name')" "$resource_name"
  assert_equal "$(echo "$created_resource_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_metadata_labels_preserved "$source_resource_json" "$created_resource_json"
  assert_equal "$(echo "$created_resource_json" | jq -r '.metadata.labels.migrated_from')" "$source_resource_id"
  assert_not_equal "$(echo "$created_resource_json" | jq -r '.metadata.labels.migration_run // empty')" ""

  local source_resource_value_json
  run_otdfctl_registered_resource_values get --id "$source_value_id" --json
  source_resource_value_json="$output"

  local created_resource_value_json
  created_resource_value_json=$(registered_resource_value_json_by_migrated_from "$created_resource_id" "$source_value_id")
  assert_not_equal "$created_resource_value_json" ""

  local created_resource_value_id
  created_resource_value_id=$(echo "$created_resource_value_json" | jq -r '.id // empty')
  assert_not_equal "$created_resource_value_id" ""
  assert_not_equal "$created_resource_value_id" "$source_value_id"

  assert_equal "$(echo "$created_resource_value_json" | jq -r '.value')" "$resource_value"
  assert_equal "$(echo "$created_resource_value_json" | jq -r '.action_attribute_values | length')" "1"
  assert_equal "$(echo "$created_resource_value_json" | jq -r '.action_attribute_values[0].action.id')" "$expected_action_target_id"
  assert_equal "$(echo "$created_resource_value_json" | jq -r '.action_attribute_values[0].attribute_value.id')" "$attribute_value_id"
  assert_metadata_labels_preserved "$source_resource_value_json" "$created_resource_value_json"
  assert_equal "$(echo "$created_resource_value_json" | jq -r '.metadata.labels.migrated_from')" "$source_value_id"
  assert_not_equal "$(echo "$created_resource_value_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_registered_resource_already_migrated_in_namespace() {
  local source_resource_id="$1"
  local namespace_id="$2"
  local existing_resource_id="$3"

  local source_resource_json
  run_otdfctl_registered_resources get --id "$source_resource_id" --json
  source_resource_json="$output"

  local existing_resource_json
  run_otdfctl_registered_resources get --id "$existing_resource_id" --json
  existing_resource_json="$output"

  assert_equal "$(echo "$existing_resource_json" | jq -r '.id // empty')" "$existing_resource_id"
  assert_equal "$(echo "$existing_resource_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(echo "$existing_resource_json" | jq -r '.name')" "$(echo "$source_resource_json" | jq -r '.name')"
  assert_equal "$(registered_resource_values_signature "$existing_resource_json")" "$(registered_resource_values_signature "$source_resource_json")"
}

assert_registered_resource_value_uses_action() {
  local value_id="$1"
  local expected_action_id="$2"
  local attribute_value_id="$3"

  local value_json
  run_otdfctl_registered_resource_values get --id "$value_id" --json
  value_json="$output"

  assert_equal "$(echo "$value_json" | jq -r '.action_attribute_values | length')" "1"
  assert_equal "$(echo "$value_json" | jq -r '.action_attribute_values[0].action.id')" "$expected_action_id"
  assert_equal "$(echo "$value_json" | jq -r '.action_attribute_values[0].attribute_value.id')" "$attribute_value_id"
}

assert_legacy_registered_resource_still_exists() {
  local source_resource_id="$1"
  local source_value_id="$2"
  local resource_name="$3"
  local resource_value="$4"

  local legacy_resource_json
  run_otdfctl_registered_resources get --id "$source_resource_id" --json
  legacy_resource_json="$output"

  assert_equal "$(echo "$legacy_resource_json" | jq -r '.id // empty')" "$source_resource_id"
  assert_equal "$(echo "$legacy_resource_json" | jq -r '.name')" "$resource_name"
  assert_equal "$(echo "$legacy_resource_json" | jq -r '.namespace.id // empty')" ""

  local legacy_resource_value_json
  run_otdfctl_registered_resource_values get --id "$source_value_id" --json
  legacy_resource_value_json="$output"

  assert_equal "$(echo "$legacy_resource_value_json" | jq -r '.id // empty')" "$source_value_id"
  assert_equal "$(echo "$legacy_resource_value_json" | jq -r '.value')" "$resource_value"
}

assert_obligation_trigger_created_in_namespace() {
  local source_trigger_id="$1"
  local namespace_id="$2"
  local attribute_value_id="$3"
  local obligation_value_id="$4"
  local action_name="$5"
  local source_action_id="$6"
  local expected_action_status="$7"
  local client_id="$8"

  case "$expected_action_status" in
    create)
      assert_custom_action_created_in_namespace "$action_name" "$source_action_id" "$namespace_id"
      ;;
    existing_standard)
      assert_standard_action_resolved_in_namespace "$action_name" "$namespace_id"
      ;;
    *)
      false
      ;;
  esac

  local expected_action_target_id
  expected_action_target_id=$(action_id_by_name_in_namespace "$action_name" "$namespace_id")

  local source_trigger_json
  source_trigger_json=$(obligation_trigger_json_by_id "$source_trigger_id" "$namespace_id")

  local created_trigger_json
  created_trigger_json=$(obligation_trigger_json_by_migrated_from "$namespace_id" "$source_trigger_id")
  assert_not_equal "$created_trigger_json" ""

  local created_trigger_id
  created_trigger_id=$(echo "$created_trigger_json" | jq -r '.id // empty')
  assert_not_equal "$created_trigger_id" ""
  assert_not_equal "$created_trigger_id" "$source_trigger_id"

  assert_equal "$(echo "$created_trigger_json" | jq -r '.attribute_value.id')" "$attribute_value_id"
  assert_equal "$(echo "$created_trigger_json" | jq -r '.action.id')" "$expected_action_target_id"
  assert_equal "$(echo "$created_trigger_json" | jq -r '.obligation_value.id')" "$obligation_value_id"
  assert_equal "$(echo "$created_trigger_json" | jq -r '.context | length')" "1"
  assert_equal "$(echo "$created_trigger_json" | jq -r '.context[0].pep.client_id')" "$client_id"
  assert_metadata_labels_preserved "$source_trigger_json" "$created_trigger_json"
  assert_equal "$(echo "$created_trigger_json" | jq -r '.metadata.labels.migrated_from')" "$source_trigger_id"
  assert_not_equal "$(echo "$created_trigger_json" | jq -r '.metadata.labels.migration_run // empty')" ""
}

assert_obligation_trigger_already_migrated_in_namespace() {
  local source_trigger_id="$1"
  local namespace_id="$2"
  local existing_trigger_id="$3"

  assert_not_equal "$existing_trigger_id" ""

  local source_trigger_json
  source_trigger_json=$(obligation_trigger_json_by_id "$source_trigger_id" "$namespace_id")

  local existing_trigger_json
  existing_trigger_json=$(obligation_trigger_json_by_id "$existing_trigger_id" "$namespace_id")

  assert_equal "$(echo "$existing_trigger_json" | jq -r '.id // empty')" "$existing_trigger_id"
  assert_equal "$(echo "$existing_trigger_json" | jq -r '.attribute_value.id')" "$(echo "$source_trigger_json" | jq -r '.attribute_value.id')"
  assert_equal "$(echo "$existing_trigger_json" | jq -r '.obligation_value.id')" "$(echo "$source_trigger_json" | jq -r '.obligation_value.id')"
  assert_equal \
    "$(echo "$existing_trigger_json" | jq -c '(.context // []) | map(.pep.client_id // "") | sort')" \
    "$(echo "$source_trigger_json" | jq -c '(.context // []) | map(.pep.client_id // "") | sort')"

  local existing_action_id
  existing_action_id=$(echo "$existing_trigger_json" | jq -r '.action.id // empty')
  assert_not_equal "$existing_action_id" ""

  local existing_action_json
  run_otdfctl_action get --id "$existing_action_id" --json
  existing_action_json="$output"

  assert_equal "$(echo "$existing_action_json" | jq -r '.id // empty')" "$existing_action_id"
  assert_equal "$(echo "$existing_action_json" | jq -r '.namespace.id')" "$namespace_id"
}

assert_legacy_obligation_trigger_still_exists() {
  local source_trigger_id="$1"
  local namespace_id="$2"
  local attribute_value_id="$3"
  local action_id="$4"
  local obligation_value_id="$5"
  local client_id="$6"

  assert_not_equal "$source_trigger_id" ""

  local legacy_trigger_json
  legacy_trigger_json=$(obligation_trigger_json_by_id "$source_trigger_id" "$namespace_id")

  assert_equal "$(echo "$legacy_trigger_json" | jq -r '.id // empty')" "$source_trigger_id"
  assert_equal "$(echo "$legacy_trigger_json" | jq -r '.attribute_value.id')" "$attribute_value_id"
  assert_equal "$(echo "$legacy_trigger_json" | jq -r '.action.id')" "$action_id"
  assert_equal "$(echo "$legacy_trigger_json" | jq -r '.action.namespace.id // empty')" ""
  assert_equal "$(echo "$legacy_trigger_json" | jq -r '.obligation_value.id')" "$obligation_value_id"
  assert_equal "$(echo "$legacy_trigger_json" | jq -r '.context[0].pep.client_id')" "$client_id"
}

assert_scs_already_migrated_in_namespace() {
  local source_scs_id="$1"
  local namespace_id="$2"
  local existing_scs_id="$3"

  local source_scs_json
  run_otdfctl_scs get --id "$source_scs_id" --json
  source_scs_json="$output"

  local existing_scs_json
  run_otdfctl_scs get --id "$existing_scs_id" --json
  existing_scs_json="$output"

  assert_equal "$(echo "$existing_scs_json" | jq -r '.id // empty')" "$existing_scs_id"
  assert_equal "$(echo "$existing_scs_json" | jq -r '.namespace.id')" "$namespace_id"
  assert_equal "$(subject_sets_signature "$existing_scs_json")" "$(subject_sets_signature "$source_scs_json")"
}

assert_legacy_scs_still_exists() {
  local source_scs_id="$1"

  local legacy_scs_json
  run_otdfctl_scs get --id "$source_scs_id" --json
  legacy_scs_json="$output"

  assert_equal "$(echo "$legacy_scs_json" | jq -r '.id // empty')" "$source_scs_id"
  assert_equal "$(echo "$legacy_scs_json" | jq -r '.namespace.id // empty')" ""
}

run_namespaced_policy_commit() {
  local scope="$1"

  run_otdfctl_migrate --commit namespaced-policy --scope "$scope"
}

setup() {
  bats_load_library bats-support
  bats_load_library bats-assert
  export TEST_PREFIX="${MIGRATION_TEST_PREFIX}-t${BATS_TEST_NUMBER}"
  export TRACKED_ACTION_IDS=""
  export TRACKED_REGISTERED_RESOURCE_IDS=""
  export TRACKED_REGISTERED_RESOURCE_VALUE_IDS=""
  export TRACKED_SCS_IDS=""
  export TRACKED_SUBJECT_MAPPING_IDS=""
  export TRACKED_OBLIGATION_TRIGGER_IDS=""
}

setup_file() {
  bats_load_library bats-support
  bats_load_library bats-assert
  export WITH_CREDS='--with-client-creds-file ./creds.json'
  export HOST='--host http://localhost:8080'

  export MIGRATION_TEST_PREFIX="np-migrate-$(date +%s)"
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

  local global_read_json
  run_otdfctl_action get --name read --json
  global_read_json="$output"
  export GLOBAL_READ_ID
  GLOBAL_READ_ID=$(echo "$global_read_json" | jq -r '.id // empty')
  assert_not_equal "$GLOBAL_READ_ID" ""
}

teardown() {
  local obligation_trigger_id
  local delete_output
  local delete_status
  while IFS= read -r obligation_trigger_id; do
    [ -n "$obligation_trigger_id" ] || continue
    if delete_output=$(./otdfctl $HOST $WITH_CREDS policy obligations triggers delete --id "$obligation_trigger_id" --force 2>&1); then
      :
    else
      delete_status=$?
      echo "warning: failed to delete obligation trigger fixture $obligation_trigger_id during teardown (exit $delete_status): $delete_output" >&2
    fi
  done <<< "$TRACKED_OBLIGATION_TRIGGER_IDS"

  local resource_value_id
  while IFS= read -r resource_value_id; do
    [ -n "$resource_value_id" ] || continue
    if delete_output=$(./otdfctl $HOST $WITH_CREDS policy registered-resources values delete --id "$resource_value_id" --force 2>&1); then
      :
    else
      delete_status=$?
      echo "warning: failed to delete registered resource value fixture $resource_value_id during teardown (exit $delete_status): $delete_output" >&2
    fi
  done <<< "$TRACKED_REGISTERED_RESOURCE_VALUE_IDS"

  local resource_id
  while IFS= read -r resource_id; do
    [ -n "$resource_id" ] || continue
    if delete_output=$(./otdfctl $HOST $WITH_CREDS policy registered-resources delete --id "$resource_id" --force 2>&1); then
      :
    else
      delete_status=$?
      echo "warning: failed to delete registered resource fixture $resource_id during teardown (exit $delete_status): $delete_output" >&2
    fi
  done <<< "$TRACKED_REGISTERED_RESOURCE_IDS"

  local subject_mapping_id
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

  unset HOST WITH_CREDS MIGRATION_TEST_PREFIX TEST_PREFIX
  unset NS_A_NAME NS_B_NAME NS_A_FQN NS_B_FQN NS_A_ID NS_B_ID
  unset ATTR_A_ID ATTR_A_VAL_1_ID ATTR_A_VAL_2_ID ATTR_B_ID ATTR_B_VAL_1_ID
  unset GLOBAL_READ_ID
  unset TRACKED_ACTION_IDS TRACKED_REGISTERED_RESOURCE_IDS TRACKED_REGISTERED_RESOURCE_VALUE_IDS
  unset TRACKED_SCS_IDS TRACKED_SUBJECT_MAPPING_IDS TRACKED_OBLIGATION_TRIGGER_IDS
}

# Asserts action-scope migration can fan out one legacy custom action into
# multiple namespaces when registered-resource and obligation-trigger anchors
# reference it across those namespaces, does not create unrelated namespaced
# objects as a side effect, and is idempotent on rerun.
@test "migrate namespaced-policy actions fans out custom actions from RR and trigger anchors" {
  local custom_action_name="${TEST_PREFIX}-download"
  local shared_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-shared"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local custom_action_labels=(--label "test_case=actions" --label "fixture=${TEST_PREFIX}-custom-action")
  local rr_a_name="${TEST_PREFIX}-repo-a"
  local rr_a_value="${TEST_PREFIX}-repo-a-main"
  local rr_a_labels=(--label "test_case=actions" --label "fixture=${TEST_PREFIX}-rr-a")
  local rr_a_value_labels=(--label "test_case=actions" --label "fixture=${TEST_PREFIX}-rr-a-value")
  local obligation_b_name="${TEST_PREFIX}-notify-b"
  local obligation_b_value="${TEST_PREFIX}-notify-b-default"
  local trigger_b_client_id="${TEST_PREFIX}-client-b"
  local trigger_b_labels=(--label "test_case=actions" --label "fixture=${TEST_PREFIX}-trigger-b")
  local custom_action_id
  local shared_scs_id
  local read_anchor_mapping_id
  local rr_a_id
  local rr_a_value_id
  local obligation_b_id
  local obligation_b_value_id
  local trigger_b_id
  local ns_a_state_before
  local ns_b_state_before
  local ns_a_state_after
  local ns_b_state_after

  create_global_action custom_action_id "$custom_action_name" "${custom_action_labels[@]}"
  create_global_scs shared_scs_id "$shared_scs"
  create_legacy_subject_mapping read_anchor_mapping_id "$ATTR_A_VAL_1_ID" "$GLOBAL_READ_ID" "$shared_scs_id"
  create_global_registered_resource rr_a_id "$rr_a_name" "${rr_a_labels[@]}"
  create_registered_resource_value rr_a_value_id "$rr_a_id" "$rr_a_value" --action-attribute-value "$custom_action_id;$ATTR_A_VAL_2_ID" "${rr_a_value_labels[@]}"

  create_namespaced_obligation obligation_b_id "$NS_B_ID" "$obligation_b_name" --label "test_case=actions" --label "fixture=${TEST_PREFIX}-obligation-b"
  create_obligation_value obligation_b_value_id "$obligation_b_id" "$obligation_b_value" --label "test_case=actions" --label "fixture=${TEST_PREFIX}-obligation-b-value"
  create_legacy_obligation_trigger trigger_b_id "$ATTR_B_VAL_1_ID" "$custom_action_id" "$obligation_b_value_id" --client-id "$trigger_b_client_id" "${trigger_b_labels[@]}"

  ns_a_state_before=$(namespace_state_json "$NS_A_ID")
  ns_b_state_before=$(namespace_state_json "$NS_B_ID")

  run_namespaced_policy_commit "actions"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 1 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 1 0 0 0 0

  assert_custom_action_created_in_namespace "$custom_action_name" "$custom_action_id" "$NS_A_ID"
  assert_custom_action_created_in_namespace "$custom_action_name" "$custom_action_id" "$NS_B_ID"

  assert_legacy_custom_action_still_exists "$custom_action_id" "$custom_action_name"
  assert_legacy_scs_still_exists "$shared_scs_id"
  assert_legacy_subject_mapping_still_exists "$ATTR_A_VAL_1_ID" "$read_anchor_mapping_id"
  assert_legacy_registered_resource_still_exists "$rr_a_id" "$rr_a_value_id" "$rr_a_name" "$rr_a_value"
  assert_legacy_obligation_trigger_still_exists "$trigger_b_id" "$NS_B_ID" "$ATTR_B_VAL_1_ID" "$custom_action_id" "$obligation_b_value_id" "$trigger_b_client_id"

  # Re-running the same migration should be idempotent. No namespace-scoped
  # counts should change on the second pass.
  local custom_action_ns_a_target_id
  local custom_action_ns_b_target_id
  custom_action_ns_a_target_id=$(action_id_by_name_in_namespace "$custom_action_name" "$NS_A_ID")
  custom_action_ns_b_target_id=$(action_id_by_name_in_namespace "$custom_action_name" "$NS_B_ID")

  ns_a_state_before="$ns_a_state_after"
  ns_b_state_before="$ns_b_state_after"

  run_namespaced_policy_commit "actions"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_action_already_migrated_in_namespace "$custom_action_name" "$NS_A_ID" "$custom_action_ns_a_target_id"
  assert_action_already_migrated_in_namespace "$custom_action_name" "$NS_B_ID" "$custom_action_ns_b_target_id"
}

# Asserts SCS-scope migration creates missing namespaced SCS targets, reuses an
# already-migrated canonical target when present, preserves subject_sets and
# metadata, does not create unrelated namespaced objects as a side effect, and
# is idempotent on rerun.
@test "migrate namespaced-policy subject-condition-sets creates single-namespace targets and reuses existing fanout targets" {
  local fanout_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-shared"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local single_namespace_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-a-only"],"subject_external_selector_value":".team.name"}],"boolean_operator":1}]}]'
  local fanout_scs_labels=(--label "test_case=scs" --label "fixture=${TEST_PREFIX}-fanout-scs")
  local single_namespace_scs_labels=(--label "test_case=scs" --label "fixture=${TEST_PREFIX}-single-scs")
  local fanout_scs_id
  local single_namespace_scs_id
  local existing_fanout_ns_b_scs_id
  local ns_a_state_before
  local ns_b_state_before
  local ns_a_state_after
  local ns_b_state_after

  create_global_scs fanout_scs_id "$fanout_scs" "${fanout_scs_labels[@]}"
  create_global_scs single_namespace_scs_id "$single_namespace_scs" "${single_namespace_scs_labels[@]}"
  create_namespaced_scs existing_fanout_ns_b_scs_id "$NS_B_ID" "$fanout_scs"

  local ignored_mapping_id
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_A_VAL_1_ID" "$GLOBAL_READ_ID" "$fanout_scs_id"
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$fanout_scs_id"
  create_legacy_subject_mapping ignored_mapping_id "$ATTR_A_VAL_2_ID" "$GLOBAL_READ_ID" "$single_namespace_scs_id"

  ns_a_state_before=$(namespace_state_json "$NS_A_ID")
  ns_b_state_before=$(namespace_state_json "$NS_B_ID")

  run_namespaced_policy_commit "subject-condition-sets"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 2 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_scs_created_in_namespace "$fanout_scs_id" "$NS_A_ID"
  assert_scs_already_migrated_in_namespace "$fanout_scs_id" "$NS_B_ID" "$existing_fanout_ns_b_scs_id"

  assert_scs_created_in_namespace "$single_namespace_scs_id" "$NS_A_ID"
  assert_scs_absent_in_namespace "$single_namespace_scs_id" "$NS_B_ID"

  assert_legacy_scs_still_exists "$fanout_scs_id"
  assert_legacy_scs_still_exists "$single_namespace_scs_id"

  # Re-running the same migration should be idempotent. The previously created
  # SCS targets should now be marked already_migrated, and the pre-existing
  # canonical target should continue to resolve as already_migrated.
  local fanout_ns_a_target_id
  local single_namespace_target_id
  fanout_ns_a_target_id=$(scs_id_by_migrated_from "$NS_A_ID" "$fanout_scs_id")
  single_namespace_target_id=$(scs_id_by_migrated_from "$NS_A_ID" "$single_namespace_scs_id")

  ns_a_state_before="$ns_a_state_after"
  ns_b_state_before="$ns_b_state_after"

  run_namespaced_policy_commit "subject-condition-sets"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_scs_already_migrated_in_namespace "$fanout_scs_id" "$NS_A_ID" "$fanout_ns_a_target_id"
  assert_scs_already_migrated_in_namespace "$fanout_scs_id" "$NS_B_ID" "$existing_fanout_ns_b_scs_id"
  assert_scs_already_migrated_in_namespace "$single_namespace_scs_id" "$NS_A_ID" "$single_namespace_target_id"
  assert_scs_absent_in_namespace "$single_namespace_scs_id" "$NS_B_ID"
}

# Asserts subject-mapping migration creates missing namespaced mappings,
# rewrites both custom-action and standard-action dependencies to the correct
# target IDs, reuses an already-migrated canonical mapping when present,
# rewrites SCS dependencies, preserves source metadata on created mappings, and
# is idempotent on rerun.
@test "migrate namespaced-policy subject-mappings rewrite dependencies and reuse canonical targets" {
  local custom_action_name="${TEST_PREFIX}-download"
  local sm_a_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-sm-a"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local sm_b_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-sm-b"],"subject_external_selector_value":".team.name"}],"boolean_operator":1}]}]'
  local custom_action_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-custom-action")
  local sm_a_scs_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-sm-a-scs")
  local sm_b_scs_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-sm-b-scs")
  local mapping_custom_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-mapping-custom")
  local mapping_standard_labels=(--label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-mapping-standard")
  local custom_action_id
  local sm_a_scs_id
  local sm_b_scs_id
  local mapping_custom_id
  local mapping_standard_id
  local ns_b_read_action_id
  local existing_sm_b_scs_id
  local existing_mapping_standard_id
  local ns_a_state_before
  local ns_b_state_before
  local ns_a_state_after
  local ns_b_state_after

  create_global_action custom_action_id "$custom_action_name" "${custom_action_labels[@]}"
  create_global_scs sm_a_scs_id "$sm_a_scs" "${sm_a_scs_labels[@]}"
  create_global_scs sm_b_scs_id "$sm_b_scs" "${sm_b_scs_labels[@]}"

  create_legacy_subject_mapping mapping_custom_id "$ATTR_A_VAL_1_ID" "$custom_action_id" "$sm_a_scs_id" "${mapping_custom_labels[@]}"
  create_legacy_subject_mapping mapping_standard_id "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$sm_b_scs_id" "${mapping_standard_labels[@]}"

  lookup_namespaced_action_id ns_b_read_action_id "read" "$NS_B_ID"
  create_namespaced_scs existing_sm_b_scs_id "$NS_B_ID" "$sm_b_scs"
  create_namespaced_subject_mapping existing_mapping_standard_id "$NS_B_ID" "$ATTR_B_VAL_1_ID" "$ns_b_read_action_id" "$existing_sm_b_scs_id" --label "test_case=subject-mappings" --label "fixture=${TEST_PREFIX}-existing-mapping-standard"

  ns_a_state_before=$(namespace_state_json "$NS_A_ID")
  ns_b_state_before=$(namespace_state_json "$NS_B_ID")

  run_namespaced_policy_commit "subject-mappings"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 1 1 1 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_subject_mapping_created_in_namespace "$mapping_custom_id" "$NS_A_ID" "$ATTR_A_VAL_1_ID" "$custom_action_name" "$custom_action_id" "create" "$sm_a_scs_id"
  assert_standard_action_resolved_in_namespace "read" "$NS_B_ID"
  assert_scs_already_migrated_in_namespace "$sm_b_scs_id" "$NS_B_ID" "$existing_sm_b_scs_id"
  assert_subject_mapping_already_migrated_in_namespace "$mapping_standard_id" "$NS_B_ID" "$existing_mapping_standard_id"

  assert_legacy_subject_mapping_still_exists "$ATTR_A_VAL_1_ID" "$mapping_custom_id"
  assert_legacy_subject_mapping_still_exists "$ATTR_B_VAL_1_ID" "$mapping_standard_id"

  # Re-running the same migration should be idempotent. The custom action,
  # migrated SCS targets, and migrated subject mappings should all resolve as
  # already_migrated on the second pass. Standard read remains existing_standard.
  local custom_action_target_id
  local sm_a_scs_target_id
  local mapping_custom_target_id
  custom_action_target_id=$(action_id_by_name_in_namespace "$custom_action_name" "$NS_A_ID")
  sm_a_scs_target_id=$(scs_id_by_migrated_from "$NS_A_ID" "$sm_a_scs_id")
  mapping_custom_target_id=$(subject_mapping_id_by_migrated_from "$NS_A_ID" "$mapping_custom_id")

  ns_a_state_before="$ns_a_state_after"
  ns_b_state_before="$ns_b_state_after"

  run_namespaced_policy_commit "subject-mappings"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_action_already_migrated_in_namespace "$custom_action_name" "$NS_A_ID" "$custom_action_target_id"
  assert_standard_action_resolved_in_namespace "read" "$NS_B_ID"
  assert_scs_already_migrated_in_namespace "$sm_a_scs_id" "$NS_A_ID" "$sm_a_scs_target_id"
  assert_scs_already_migrated_in_namespace "$sm_b_scs_id" "$NS_B_ID" "$existing_sm_b_scs_id"
  assert_subject_mapping_already_migrated_in_namespace "$mapping_custom_id" "$NS_A_ID" "$mapping_custom_target_id"
  assert_subject_mapping_already_migrated_in_namespace "$mapping_standard_id" "$NS_B_ID" "$existing_mapping_standard_id"
}

# Asserts registered-resource migration creates missing namespaced targets,
# rewrites action-attribute-value bindings to migrated action IDs, reuses an
# already-migrated canonical RR target when present, preserves metadata on both
# the parent RR and value, does not create unrelated namespaced objects as a
# side effect, and is idempotent on rerun.
@test "migrate namespaced-policy registered-resources rewrites action bindings and reuses canonical targets" {
  local custom_action_name="${TEST_PREFIX}-download"
  local rr_a_name="${TEST_PREFIX}-repo-a"
  local rr_b_name="${TEST_PREFIX}-repo-b"
  local rr_a_value="${TEST_PREFIX}-repo-a-main"
  local rr_b_value="${TEST_PREFIX}-repo-b-main"
  local custom_action_labels=(--label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-custom-action")
  local rr_a_labels=(--label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-rr-a")
  local rr_b_labels=(--label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-rr-b")
  local rr_a_value_labels=(--label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-rr-a-value")
  local rr_b_value_labels=(--label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-rr-b-value")
  local custom_action_id
  local rr_a_id
  local rr_b_id
  local rr_a_value_id
  local rr_b_value_id
  local ns_b_read_action_id
  local existing_rr_b_id
  local existing_rr_b_value_id
  local ns_a_state_before
  local ns_b_state_before
  local ns_a_state_after
  local ns_b_state_after

  create_global_action custom_action_id "$custom_action_name" "${custom_action_labels[@]}"
  create_global_registered_resource rr_a_id "$rr_a_name" "${rr_a_labels[@]}"
  create_global_registered_resource rr_b_id "$rr_b_name" "${rr_b_labels[@]}"
  create_registered_resource_value rr_a_value_id "$rr_a_id" "$rr_a_value" --action-attribute-value "$custom_action_id;$ATTR_A_VAL_1_ID" "${rr_a_value_labels[@]}"
  create_registered_resource_value rr_b_value_id "$rr_b_id" "$rr_b_value" --action-attribute-value "$GLOBAL_READ_ID;$ATTR_B_VAL_1_ID" "${rr_b_value_labels[@]}"

  lookup_namespaced_action_id ns_b_read_action_id "read" "$NS_B_ID"

  run_otdfctl_registered_resources create --name "$rr_b_name" --namespace "$NS_B_ID" --label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-existing-rr-b" --json
  assert_success
  existing_rr_b_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$existing_rr_b_id" ""

  run_otdfctl_registered_resource_values create --resource "$existing_rr_b_id" --value "$rr_b_value" --action-attribute-value "$ns_b_read_action_id;$ATTR_B_VAL_1_ID" --label "test_case=registered-resources" --label "fixture=${TEST_PREFIX}-existing-rr-b-value" --json
  assert_success
  existing_rr_b_value_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$existing_rr_b_value_id" ""

  ns_a_state_before=$(namespace_state_json "$NS_A_ID")
  ns_b_state_before=$(namespace_state_json "$NS_B_ID")

  run_namespaced_policy_commit "registered-resources"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 1 0 0 1 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_registered_resource_created_in_namespace "$rr_a_id" "$rr_a_value_id" "$NS_A_ID" "$rr_a_name" "$rr_a_value" "$custom_action_name" "$custom_action_id" "create" "$ATTR_A_VAL_1_ID"

  assert_registered_resource_already_migrated_in_namespace "$rr_b_id" "$NS_B_ID" "$existing_rr_b_id"
  assert_standard_action_resolved_in_namespace "read" "$NS_B_ID"
  assert_registered_resource_value_uses_action "$existing_rr_b_value_id" "$ns_b_read_action_id" "$ATTR_B_VAL_1_ID"

  assert_legacy_registered_resource_still_exists "$rr_a_id" "$rr_a_value_id" "$rr_a_name" "$rr_a_value"
  assert_legacy_registered_resource_still_exists "$rr_b_id" "$rr_b_value_id" "$rr_b_name" "$rr_b_value"

  # Re-running the same migration should be idempotent. The previously created
  # RR target should now resolve as already_migrated, while the existing
  # canonical RR target continues to resolve as already_migrated.
  local custom_action_target_id
  local rr_a_target_id
  custom_action_target_id=$(action_id_by_name_in_namespace "$custom_action_name" "$NS_A_ID")
  rr_a_target_id=$(registered_resource_id_by_migrated_from "$NS_A_ID" "$rr_a_id")

  ns_a_state_before="$ns_a_state_after"
  ns_b_state_before="$ns_b_state_after"

  run_namespaced_policy_commit "registered-resources"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_action_already_migrated_in_namespace "$custom_action_name" "$NS_A_ID" "$custom_action_target_id"
  assert_standard_action_resolved_in_namespace "read" "$NS_B_ID"
  assert_registered_resource_already_migrated_in_namespace "$rr_a_id" "$NS_A_ID" "$rr_a_target_id"
  assert_registered_resource_already_migrated_in_namespace "$rr_b_id" "$NS_B_ID" "$existing_rr_b_id"
}

# Asserts obligation-trigger migration creates missing namespaced trigger
# targets, rewrites the referenced action to the migrated action target,
# reuses an already-migrated canonical trigger when present, preserves source
# metadata, does not create unrelated namespaced objects as a side effect, and
# is idempotent on rerun.
@test "migrate namespaced-policy obligation-triggers rewrites action dependencies and reuses canonical targets" {
  local custom_action_name="${TEST_PREFIX}-download"
  local obligation_a_name="${TEST_PREFIX}-notify-a"
  local obligation_b_name="${TEST_PREFIX}-notify-b"
  local obligation_a_value="${TEST_PREFIX}-notify-a-default"
  local obligation_b_value="${TEST_PREFIX}-notify-b-default"
  local trigger_a_client_id="${TEST_PREFIX}-client-a"
  local trigger_b_client_id="${TEST_PREFIX}-client-b"
  local custom_action_labels=(--label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-custom-action")
  local trigger_a_labels=(--label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-trigger-a")
  local custom_action_id
  local obligation_a_id
  local obligation_b_id
  local obligation_a_value_id
  local obligation_b_value_id
  local trigger_a_id
  local trigger_b_id
  local ns_b_read_action_id
  local existing_trigger_b_id
  local ns_a_state_before
  local ns_b_state_before
  local ns_a_state_after
  local ns_b_state_after

  create_global_action custom_action_id "$custom_action_name" "${custom_action_labels[@]}"
  create_namespaced_obligation obligation_a_id "$NS_A_ID" "$obligation_a_name" --label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-obligation-a"
  create_namespaced_obligation obligation_b_id "$NS_B_ID" "$obligation_b_name" --label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-obligation-b"
  create_obligation_value obligation_a_value_id "$obligation_a_id" "$obligation_a_value" --label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-obligation-a-value"
  create_obligation_value obligation_b_value_id "$obligation_b_id" "$obligation_b_value" --label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-obligation-b-value"

  create_legacy_obligation_trigger trigger_a_id "$ATTR_A_VAL_1_ID" "$custom_action_id" "$obligation_a_value_id" --client-id "$trigger_a_client_id" "${trigger_a_labels[@]}"
  create_legacy_obligation_trigger trigger_b_id "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$obligation_b_value_id" --client-id "$trigger_b_client_id" --label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-trigger-b"

  lookup_namespaced_action_id ns_b_read_action_id "read" "$NS_B_ID"

  run_otdfctl_obligation_triggers create --attribute-value "$ATTR_B_VAL_1_ID" --action "$ns_b_read_action_id" --obligation-value "$obligation_b_value_id" --client-id "$trigger_b_client_id" --label "test_case=obligation-triggers" --label "fixture=${TEST_PREFIX}-existing-trigger-b" --json
  assert_success
  existing_trigger_b_id=$(echo "$output" | jq -r '.id // empty')
  assert_not_equal "$existing_trigger_b_id" ""

  ns_a_state_before=$(namespace_state_json "$NS_A_ID")
  ns_b_state_before=$(namespace_state_json "$NS_B_ID")

  run_namespaced_policy_commit "obligation-triggers"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 1 0 0 0 1
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_obligation_trigger_created_in_namespace "$trigger_a_id" "$NS_A_ID" "$ATTR_A_VAL_1_ID" "$obligation_a_value_id" "$custom_action_name" "$custom_action_id" "create" "$trigger_a_client_id"

  assert_obligation_trigger_already_migrated_in_namespace "$trigger_b_id" "$NS_B_ID" "$existing_trigger_b_id"
  assert_standard_action_resolved_in_namespace "read" "$NS_B_ID"

  assert_legacy_obligation_trigger_still_exists "$trigger_a_id" "$NS_A_ID" "$ATTR_A_VAL_1_ID" "$custom_action_id" "$obligation_a_value_id" "$trigger_a_client_id"
  assert_legacy_obligation_trigger_still_exists "$trigger_b_id" "$NS_B_ID" "$ATTR_B_VAL_1_ID" "$GLOBAL_READ_ID" "$obligation_b_value_id" "$trigger_b_client_id"

  # Re-running the same migration should be idempotent. The previously created
  # custom action target and trigger target should resolve as already_migrated,
  # while the pre-existing canonical trigger remains already_migrated.
  local custom_action_target_id
  local trigger_a_target_id
  custom_action_target_id=$(action_id_by_name_in_namespace "$custom_action_name" "$NS_A_ID")
  trigger_a_target_id=$(obligation_trigger_id_by_migrated_from "$NS_A_ID" "$trigger_a_id")

  ns_a_state_before="$ns_a_state_after"
  ns_b_state_before="$ns_b_state_after"

  run_namespaced_policy_commit "obligation-triggers"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_action_already_migrated_in_namespace "$custom_action_name" "$NS_A_ID" "$custom_action_target_id"
  assert_standard_action_resolved_in_namespace "read" "$NS_B_ID"
  assert_obligation_trigger_already_migrated_in_namespace "$trigger_a_id" "$NS_A_ID" "$trigger_a_target_id"
  assert_obligation_trigger_already_migrated_in_namespace "$trigger_b_id" "$NS_B_ID" "$existing_trigger_b_id"
}

# Asserts selecting every migration scope together creates one namespaced
# target for each supported object type in a simple single-namespace graph and
# is idempotent on rerun.
@test "migrate namespaced-policy all scopes creates one target for each object type" {
  local custom_action_name="${TEST_PREFIX}-download"
  local all_scopes_scs='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["'"${TEST_PREFIX}"'-all-scopes"],"subject_external_selector_value":".org.name"}],"boolean_operator":1}]}]'
  local rr_name="${TEST_PREFIX}-repo"
  local rr_value="${TEST_PREFIX}-repo-main"
  local obligation_name="${TEST_PREFIX}-notify"
  local obligation_value="${TEST_PREFIX}-notify-default"
  local trigger_client_id="${TEST_PREFIX}-client"
  local custom_action_id
  local scs_id
  local mapping_id
  local rr_id
  local rr_value_id
  local obligation_id
  local obligation_value_id
  local trigger_id
  local ns_a_state_before
  local ns_b_state_before
  local ns_a_state_after
  local ns_b_state_after

  create_global_action custom_action_id "$custom_action_name" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-custom-action"
  create_global_scs scs_id "$all_scopes_scs" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-scs"
  create_legacy_subject_mapping mapping_id "$ATTR_A_VAL_1_ID" "$custom_action_id" "$scs_id" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-mapping"
  create_global_registered_resource rr_id "$rr_name" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-rr"
  create_registered_resource_value rr_value_id "$rr_id" "$rr_value" --action-attribute-value "$custom_action_id;$ATTR_A_VAL_2_ID" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-rr-value"
  create_namespaced_obligation obligation_id "$NS_A_ID" "$obligation_name" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-obligation"
  create_obligation_value obligation_value_id "$obligation_id" "$obligation_value" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-obligation-value"
  create_legacy_obligation_trigger trigger_id "$ATTR_A_VAL_1_ID" "$custom_action_id" "$obligation_value_id" --client-id "$trigger_client_id" --label "test_case=all-scopes" --label "fixture=${TEST_PREFIX}-trigger"

  ns_a_state_before=$(namespace_state_json "$NS_A_ID")
  ns_b_state_before=$(namespace_state_json "$NS_B_ID")

  run_namespaced_policy_commit "actions,subject-condition-sets,subject-mappings,registered-resources,obligation-triggers"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 1 1 1 1 1
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_custom_action_created_in_namespace "$custom_action_name" "$custom_action_id" "$NS_A_ID"

  assert_scs_created_in_namespace "$scs_id" "$NS_A_ID"

  assert_subject_mapping_created_in_namespace "$mapping_id" "$NS_A_ID" "$ATTR_A_VAL_1_ID" "$custom_action_name" "$custom_action_id" "create" "$scs_id"

  assert_registered_resource_created_in_namespace "$rr_id" "$rr_value_id" "$NS_A_ID" "$rr_name" "$rr_value" "$custom_action_name" "$custom_action_id" "create" "$ATTR_A_VAL_2_ID"

  assert_obligation_trigger_created_in_namespace "$trigger_id" "$NS_A_ID" "$ATTR_A_VAL_1_ID" "$obligation_value_id" "$custom_action_name" "$custom_action_id" "create" "$trigger_client_id"

  assert_legacy_custom_action_still_exists "$custom_action_id" "$custom_action_name"
  assert_legacy_scs_still_exists "$scs_id"
  assert_legacy_subject_mapping_still_exists "$ATTR_A_VAL_1_ID" "$mapping_id"
  assert_legacy_registered_resource_still_exists "$rr_id" "$rr_value_id" "$rr_name" "$rr_value"
  assert_legacy_obligation_trigger_still_exists "$trigger_id" "$NS_A_ID" "$ATTR_A_VAL_1_ID" "$custom_action_id" "$obligation_value_id" "$trigger_client_id"

  # Re-running the combined migration should be idempotent. Every target created
  # above should now resolve as already_migrated, and no namespace counts
  # should change on the second pass.
  local custom_action_target_id
  local scs_target_id
  local mapping_target_id
  local rr_target_id
  local trigger_target_id
  custom_action_target_id=$(action_id_by_name_in_namespace "$custom_action_name" "$NS_A_ID")
  scs_target_id=$(scs_id_by_migrated_from "$NS_A_ID" "$scs_id")
  mapping_target_id=$(subject_mapping_id_by_migrated_from "$NS_A_ID" "$mapping_id")
  rr_target_id=$(registered_resource_id_by_migrated_from "$NS_A_ID" "$rr_id")
  trigger_target_id=$(obligation_trigger_id_by_migrated_from "$NS_A_ID" "$trigger_id")

  ns_a_state_before="$ns_a_state_after"
  ns_b_state_before="$ns_b_state_after"

  run_namespaced_policy_commit "actions,subject-condition-sets,subject-mappings,registered-resources,obligation-triggers"
  assert_success

  ns_a_state_after=$(namespace_state_json "$NS_A_ID")
  ns_b_state_after=$(namespace_state_json "$NS_B_ID")

  assert_namespace_state_delta "$ns_a_state_before" "$ns_a_state_after" 0 0 0 0 0
  assert_namespace_state_delta "$ns_b_state_before" "$ns_b_state_after" 0 0 0 0 0

  assert_action_already_migrated_in_namespace "$custom_action_name" "$NS_A_ID" "$custom_action_target_id"
  assert_scs_already_migrated_in_namespace "$scs_id" "$NS_A_ID" "$scs_target_id"
  assert_subject_mapping_already_migrated_in_namespace "$mapping_id" "$NS_A_ID" "$mapping_target_id"
  assert_registered_resource_already_migrated_in_namespace "$rr_id" "$NS_A_ID" "$rr_target_id"
  assert_obligation_trigger_already_migrated_in_namespace "$trigger_id" "$NS_A_ID" "$trigger_target_id"
}
