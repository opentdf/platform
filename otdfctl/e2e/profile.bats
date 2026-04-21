#!/usr/bin/env bats

setup_file() {
  # Prefix for all profiles created in this file to avoid clashing
  PROFILE_TEST_PREFIX="bats-profile-$(date +%s)"
  export PROFILE_TEST_PREFIX
}

setup() {
  load "${BATS_LIB_PATH}/bats-support/load.bash"
  load "${BATS_LIB_PATH}/bats-assert/load.bash"

  run_otdfctl() {
    run bash -c "./otdfctl profile $*"
  }

  run_otdfctl_profile_keyring() {
    # LEGACY_OTDFCTL_BIN gets set in the action.yaml
    # It is v0.26.2 of otdfctl
    run bash -c "$LEGACY_OTDFCTL_BIN profile $*"
  }
}

teardown() {
  run_otdfctl profile delete-all --force
  run_otdfctl profile delete-all --store keyring --force
}

@test "profile create" {
  profile="${PROFILE_TEST_PREFIX}-create"
  run_otdfctl create "$profile" http://localhost:8080
  assert_success
  assert_output --partial "Profile ${profile} created"

  # Invalid endpoint should fail with a helpful message
  run_otdfctl create "$profile" localhost:8080
  assert_failure
  assert_output --partial "Failed to create profile"
  assert_output --partial "invalid scheme"
}

@test "profile list shows profiles and default" {
  profile1="${PROFILE_TEST_PREFIX}-list-1"
  profile2="${PROFILE_TEST_PREFIX}-list-2"

  run_otdfctl create "$profile1" http://localhost:8080
  assert_success

  run_otdfctl create "$profile2" http://localhost:8080 --set-default
  assert_success

  run_otdfctl list
  assert_success
  assert_output --partial "Listing profiles from filesystem"
  assert_output --partial "  ${profile1}"
  assert_output --partial "* ${profile2}"

  profile1_keyring="${PROFILE_TEST_PREFIX}-list-keyring-1"
  profile2_keyring="${PROFILE_TEST_PREFIX}-list-keyring-2"

  run_otdfctl_profile_keyring create "$profile1_keyring" http://localhost:8080
  assert_success

  run_otdfctl_profile_keyring create --set-default "$profile2_keyring" http://localhost:8080
  assert_success

  run_otdfctl list --store keyring
  assert_success
  assert_output --partial "Listing profiles from keyring"
  assert_output --partial "  ${profile1_keyring}"
  assert_output --partial "* ${profile2_keyring}"
}

@test "profile get shows profile details" {
  profile="${PROFILE_TEST_PREFIX}-get"

  run_otdfctl create "$profile" http://localhost:8080 --set-default
  assert_success

  run_otdfctl get "$profile"
  assert_success
  assert_output --partial "Profile"
  assert_output --partial "$profile"
  assert_output --partial "Endpoint"
  assert_output --partial "http://localhost:8080"
  assert_output --partial "Is default"
  assert_output --partial "true"

  profile_keyring="${PROFILE_TEST_PREFIX}-get-keyring"

  run_otdfctl_profile_keyring create --set-default "$profile_keyring" http://localhost:8080
  assert_success

  run_otdfctl get "$profile_keyring" --store keyring
  assert_success
  assert_output --partial "Profile"
  assert_output --partial "$profile_keyring"
  assert_output --partial "Endpoint"
  assert_output --partial "http://localhost:8080"
  assert_output --partial "Is default"
  assert_output --partial "true"
}

@test "profile delete removes profile" {
  base="${PROFILE_TEST_PREFIX}-delete"
  default_profile="${base}-default"
  target_profile="${base}-target"

  run_otdfctl create "$default_profile" http://localhost:8080 --set-default
  assert_success

  run_otdfctl create "$target_profile" http://localhost:8080
  assert_success

  run_otdfctl delete "$target_profile"
  assert_success
  assert_output --partial "Deleted profile ${target_profile} from filesystem"

  run_otdfctl profile list
  assert_success
  refute_output --partial "$target_profile"

  base_keyring="${PROFILE_TEST_PREFIX}-delete-keyring"
  default_profile_keyring="${base_keyring}-default"
  target_profile_keyring="${base_keyring}-target"

  run_otdfctl_profile_keyring create --set-default "$default_profile_keyring" http://localhost:8080
  assert_success

  run_otdfctl_profile_keyring create "$target_profile_keyring" http://localhost:8080
  assert_success

  run_otdfctl delete "$target_profile_keyring" --store keyring
  assert_success
  assert_output --partial "Deleted profile ${target_profile_keyring} from keyring"

  run_otdfctl list --store keyring
  assert_success
  refute_output --partial "$target_profile_keyring"
}

@test "profile set-default updates default profile" {
  base="${PROFILE_TEST_PREFIX}-set-default"
  profile1="${base}-1"
  profile2="${base}-2"

  run_otdfctl create "$profile1" http://localhost:8080 --set-default
  assert_success

  run_otdfctl create "$profile2" http://localhost:8081
  assert_success

  run_otdfctl set-default "$profile2"
  assert_success
  assert_output --partial "Set profile ${profile2} as default"

  run_otdfctl list
  assert_success
  assert_output --partial "* ${profile2}"
}

@test "profile set-endpoint updates endpoint" {
  profile="${PROFILE_TEST_PREFIX}-set-endpoint"

  run_otdfctl create "$profile" http://localhost:8080
  assert_success

  run_otdfctl set-endpoint "$profile" http://localhost:8081
  assert_success
  assert_output --partial "Set endpoint http://localhost:8081 for profile ${profile}"

  run_otdfctl get "$profile"
  assert_success
  assert_output --partial "http://localhost:8081"
}

@test "profile delete-all deletes all profiles" {
  base="${PROFILE_TEST_PREFIX}-delete-all"
  profile1="${base}-1"
  profile2="${base}-2"

  run_otdfctl create "$profile1" http://localhost:8080 --set-default
  assert_success

  run_otdfctl create "$profile2" http://localhost:8081
  assert_success

  run_otdfctl delete-all --force
  assert_success
  assert_output --regexp '^Deleted [0-9]+ profiles from filesystem$'

  run_otdfctl list
  assert_success
  refute_output --partial "$profile1"
  refute_output --partial "$profile2"

  base_keyring="${PROFILE_TEST_PREFIX}-delete-all-keyring"
  profile1_keyring="${base_keyring}-1"
  profile2_keyring="${base_keyring}-2"

  run_otdfctl_profile_keyring create --set-default "$profile1_keyring" http://localhost:8080
  assert_success

  run_otdfctl_profile_keyring create "$profile2_keyring" http://localhost:8081
  assert_success

  run_otdfctl delete-all --store keyring --force
  assert_success
  assert_output --regexp '^Deleted [0-9]+ profiles from keyring$'

  run_otdfctl list --store keyring
  assert_success
  refute_output --partial "$profile1_keyring"
  refute_output --partial "$profile2_keyring"
}

@test "profile migrate moves keyring profiles to filesystem" {
  base="${PROFILE_TEST_PREFIX}-migrate"
  profile1="${base}-1"
  profile2="${base}-2"

  run_otdfctl_profile_keyring create --set-default "$profile1" http://localhost:8080
  assert_success

  run_otdfctl_profile_keyring create "$profile2" http://localhost:8081
  assert_success

  run_otdfctl list --store keyring
  assert_success
  assert_output --partial "$profile1"
  assert_output --partial "$profile2"

  run_otdfctl list
  assert_success
  refute_output --partial "$profile1"
  refute_output --partial "$profile2"

  run_otdfctl migrate
  assert_success
  assert_output --partial "Migration complete."

  run_otdfctl list
  assert_success
  assert_output --partial "Listing profiles from filesystem"
  assert_output --partial "* ${profile1}"
  assert_output --partial "  ${profile2}"

  run_otdfctl list --store keyring
  assert_success
  assert_output --partial "Listing profiles from keyring"
  refute_output --partial "$profile1"
  refute_output --partial "$profile2"
}

@test "profile keyring cleanup removes all keyring profiles" {
  base="${PROFILE_TEST_PREFIX}-cleanup"
  profile1="${base}-1"
  profile2="${base}-2"

  run_otdfctl_profile_keyring create "$profile1" http://localhost:8080
  assert_success

  run_otdfctl_profile_keyring create "$profile2" http://localhost:8081
  assert_success

  run_otdfctl list --store keyring
  assert_success
  assert_output --partial "$profile1"
  assert_output --partial "$profile2"

  run_otdfctl cleanup --force
  assert_success
  assert_output --partial "Keyring profile store cleanup complete"

  run_otdfctl list --store keyring
  assert_success
  refute_output --partial "$profile1"
  refute_output --partial "$profile2"
}
