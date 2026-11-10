#!/usr/bin/env bash


run_otdfctl_key() {
  run sh -c "./otdfctl policy kas-registry key $HOST $WITH_CREDS $*"
}

delete_all_keys_in_kas() {
  local kas_id="$1"
  echo "Attempting to delete all keys in KAS registry: $kas_id"

  # List all keys in the specified KAS registry
  run_otdfctl_key list --kas "$kas_id" --json
  assert_success

  local key_ids=()
  local keys_to_delete=$(echo "$output" | jq -c '.kas_keys[] | {id: .key.id, key_id: .key.key_id, kas_uri: .kas_uri}')

  if [ -z "$keys_to_delete" ]; then
    echo "No keys found to delete in KAS registry: $kas_id"
    return 0
  fi

  echo "Found $(echo "$keys_to_delete" | wc -l | xargs) keys to delete in KAS registry: $kas_id"
  echo "$keys_to_delete" | while read -r key_info; do
    local key_system_id=$(echo "$key_info" | jq -r '.id')
    local kid=$(echo "$key_info" | jq -r '.key_id')
    local key_kas_uri=$(echo "$key_info" | jq -r '.kas_uri')

    echo "Deleting key: $key_user_id (system ID: $key_system_id) from KAS URI: $key_kas_uri"
    run_otdfctl_key unsafe delete --id "$key_system_id" --kas-uri "$key_kas_uri" --key-id "$kid" --force
    assert_success
    if [ "$status" -ne 0 ]; then
      echo "Warning: Failed to delete key $key_system_id. Error: $output" >&2
    else
      echo "Successfully deleted key: $key_system_id"
    fi
  done
}


delete_kas_registry() {
  local kas_id="$1"
  run sh -c "./otdfctl $HOST $WITH_CREDS policy kas-registry delete --id "$kas_id" --force"
  assert_success
}

delete_provider_config() {
  local pc_id="$1"
  run sh -c "./otdfctl $HOST $WITH_CREDS policy keymanagement provider delete --id "$pc_id" --force"
  assert_success
}
