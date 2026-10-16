#!/usr/bin/env bats

# General miscellaneous tests

setup_file() {
    export WITH_CREDS='--with-client-creds-file ./creds.json'
    export HOST='--host http://localhost:8080'
}

setup() {
    bats_load_library bats-support
    bats_load_library bats-assert

    # invoke binary with credentials
    run_otdfctl () {
      run sh -c "./otdfctl $*"
    }
}

teardown_file() {
  # clear out all test env vars
  unset HOST WITH_CREDS
  rm -rf bad_creds.json
}

@test "Linux auth uses an encrypted filesystem profile" {
    [[ "$(uname -s)" == "Linux" ]] || skip "Linux filesystem authentication regression"
    [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || skip "requires an unlocked Secret Service keyring"
    profile_home="${BATS_TEST_TMPDIR}/auth-profile"
    mkdir -p "$profile_home"

    run env HOME="$profile_home" ./otdfctl profile create linux-auth http://127.0.0.1:1 --set-default
    assert_success

    run env HOME="$profile_home" ./otdfctl auth client-credentials test-client test-secret
    assert_failure
    assert_output --partial 'An error occurred during login'
    refute_output --partial 'Keyring storage is not available on Linux'

    run env HOME="$profile_home" ./otdfctl auth logout
    assert_success
    assert_output --partial 'Profile: [linux-auth], logged out'
}

@test "helpful error if wrong platform endpoint host" {
    BAD_HOST='--host http://localhost:9000'
    run_otdfctl $BAD_HOST $WITH_CREDS policy attributes list
    assert_failure
    assert_output --partial "Failed to connect to the platform. Is the platform accepting connections at"
}

@test "helpful error if bad credentials" {
    # nonexistent client creds
    echo -n '{"clientId":"badClient","clientSecret":"badSecret"}' > bad_creds.json
    BAD_CREDS="--with-client-creds-file ./bad_creds.json"
    run_otdfctl $HOST $BAD_CREDS policy attributes list
    assert_failure
    assert_output --partial "Failed to authenticate with flag-provided client credentials"

    # malformed JSON
    BAD_CREDS="--with-client-creds '{clientId:"badClient",clientSecret:"badSecret"}'"
    run_otdfctl $HOST $BAD_CREDS policy attributes list
    assert_failure
    assert_output --partial "Failed to get client credentials"
}

@test "helpful error if missing client credentials" {
    run_otdfctl $HOST policy attributes list
    assert_failure
    assert_output --partial "One of"
    assert_output --partial "must be set: when using global flags"
}

@test "helpful error if missing host" {
    run_otdfctl $WITH_CREDS policy attributes list
    assert_failure
    assert_output --partial "Host must be set: when using global flags"
}
