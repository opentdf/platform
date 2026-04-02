#!/usr/bin/env bats

# Tests for kas registry

setup_file() {
    export CREDSFILE=creds.json
    echo -n '{"clientId":"opentdf","clientSecret":"secret"}' >$CREDSFILE
    export WITH_CREDS="--with-client-creds-file $CREDSFILE"
    export HOST='--host http://localhost:8080'
    export DEBUG_LEVEL="--log-level debug"
}

setup() {
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"

    # invoke binary with credentials
    run_otdfctl_kasr() {
        run sh -c "./otdfctl policy kas-registry $HOST $WITH_CREDS $*"
    }
}

teardown() {
    ID=$(echo "$CREATED" | jq -r '.id')
    run_otdfctl_kasr delete --id "$ID" --force
}

@test "create KAS registration with invalid URI - fails" {
    BAD_URIS=(
        "no-scheme.co"
        "localhost"
        "http://example.com:abc"
        "https ://example.com"
    )

    for URI in "${BAD_URIS[@]}"; do
        run_otdfctl_kasr create --uri "$URI"
        assert_failure
        assert_output --partial "Failed to create Registered KAS"
        assert_output --partial "uri: "
    done
}

@test "create KAS registration with duplicate URI - fails" {
    URI="https://testing-duplication.io"
    run_otdfctl_kasr create --uri "$URI"
    assert_success
    export CREATED="$output"
    run_otdfctl_kasr create --uri "$URI"
    assert_failure
    assert_output --partial "Failed to create Registered KAS entry"
    assert_output --partial "already_exists"
}

@test "create KAS registration with duplicate name - fails" {
    NAME="duplicate_name_kas"
    run_otdfctl_kasr create --uri "https://testing-duplication.name.io" -n "$NAME"
    assert_success
    run_otdfctl_kasr create --uri "https://testing-duplication.name.net" -n "$NAME"
    assert_failure
    assert_output --partial "Failed to create Registered KAS entry"
    assert_output --partial "already_exists"
}

@test "create KAS registration with invalid name - fails" {
    URI="http://creating.kas.invalid.name/kas"
    BAD_NAMES=(
        "-bad-name"
        "bad-name-"
        "_bad_name"
        "bad_name_"
        "name@with!special#chars"
        "$(printf 'a%.0s' {1..254})" # Generates a string of 254 'a' characters
    )

    for NAME in "${BAD_NAMES[@]}"; do
        echo "testing $NAME"
        run_otdfctl_kasr create --uri "$URI" -n "$NAME"
        assert_failure
        assert_output --partial "Failed to create Registered KAS"
        assert_output --partial "name: "
    done
}

@test "update registered KAS" {
    URI="https://testing-update.net"
    NAME="new-kas-testing-update"
    export CREATED=$(./otdfctl $HOST $DEBUG_LEVEL $WITH_CREDS policy kas-registry create --uri "$URI" -n "$NAME" --json)
    ID=$(echo "$CREATED" | jq -r '.id')
    run_otdfctl_kasr update --id "$ID" -u "https://newuri.com" -n "newer-name" --json
    assert_output --partial "$ID"
    assert_output --partial "https://newuri.com"
    assert_output --partial "newer-name"
    refute_output --partial "$NAME"
    refute_output --partial "$URI"
}

@test "update registered KAS with invalid URI - fails" {
    export CREATED=$(./otdfctl $HOST $DEBUG_LEVEL $WITH_CREDS policy kas-registry create --uri "https://bad-update.uri.kas" --json)
    ID=$(echo "$CREATED" | jq -r '.id')
    BAD_URIS=(
        "no-scheme.co"
        "localhost"
        "http://example.com:abc"
        "https ://example.com"
    )

    for URI in "${BAD_URIS[@]}"; do
        run_otdfctl_kasr update -i "$ID" --uri "$URI"
        assert_failure
        assert_output --partial "$ID"
        assert_output --partial "Failed to update Registered KAS entry"
        assert_output --partial "uri: "
    done
}

@test "update registered KAS with invalid name - fails" {
    export CREATED=$(./otdfctl $HOST $DEBUG_LEVEL $WITH_CREDS policy kas-registry create --uri "https://bad-update.name.kas" --json)
    ID=$(echo "$CREATED" | jq -r '.id')
    BAD_NAMES=(
        "-bad-name"
        "bad-name-"
        "_bad_name"
        "bad_name_"
        "name@with!special#chars"
        "$(printf 'a%.0s' {1..254})" # Generates a string of 254 'a' characters
    )

    for NAME in "${BAD_NAMES[@]}"; do
        run_otdfctl_kasr update --id "$ID" --name "$NAME"
        assert_failure
        assert_output --partial "Failed to update Registered KAS"
        assert_output --partial "name: "
    done
}

@test "list registered KASes" {
    URI="https://testing-list.io"
    NAME="listed-kas"
    export CREATED=$(./otdfctl $HOST $DEBUG_LEVEL $WITH_CREDS policy kas-registry create --uri "$URI" -n "$NAME" --json)
    ID=$(echo "$CREATED" | jq -r '.id')
    run_otdfctl_kasr list --json
    assert_output --partial "$ID"
    assert_output --partial "uri"
    assert_output --partial "$URI"
    assert_output --partial "name"
    assert_output --partial "$NAME"

    run_otdfctl_kasr list
    assert_output --partial "Total"
    assert_line --regexp "Current Offset.*0"

    run_otdfctl_kasr list --json
    assert_success
    assert_not_equal $(echo "$output" | jq -r ".pagination") "null"
    total=$(echo "$output" | jq -r ".pagination.total")
    [[ $total -ge 1 ]]
}
