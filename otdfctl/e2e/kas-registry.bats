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
    bats_load_library bats-support
    bats_load_library bats-assert

    # invoke binary with credentials
    run_otdfctl_kasr() {
        run sh -c "./otdfctl policy kas-registry $HOST $WITH_CREDS $*"
    }
}

teardown() {
    if [[ -z "${CREATED:-}" ]]; then
        return
    fi

    ID=$(echo "$CREATED" | jq -r '.id')
    if [[ -n "$ID" ]]; then
        run_otdfctl_kasr delete --id "$ID" --force
    fi
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

@test "list registered KASes supports sort fields and partial sort syntax" {
    export CREATED=""
    sort_prefix="sort-kas-$BATS_TEST_NUMBER-$RANDOM"
    kas_a=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --name "$sort_prefix-alpha" --uri "https://$sort_prefix-alpha.example.com" --json)
    sleep 1
    kas_b=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --name "$sort_prefix-bravo" --uri "https://$sort_prefix-bravo.example.com" --json)
    sleep 1
    kas_c=$(./otdfctl $HOST $WITH_CREDS policy kas-registry create --name "$sort_prefix-charlie" --uri "https://$sort_prefix-charlie.example.com" --json)
    kas_a_id=$(echo "$kas_a" | jq -r '.id')
    kas_b_id=$(echo "$kas_b" | jq -r '.id')
    kas_c_id=$(echo "$kas_c" | jq -r '.id')

    run_otdfctl_kasr list --sort name:asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg prefix "$sort_prefix" '[.key_access_servers[] | select((.name // "") | startswith($prefix)) | .id] | join(",")')" "$kas_a_id,$kas_b_id,$kas_c_id"

    run_otdfctl_kasr list --sort name:desc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg prefix "$sort_prefix" '[.key_access_servers[] | select((.name // "") | startswith($prefix)) | .id] | join(",")')" "$kas_c_id,$kas_b_id,$kas_a_id"

    run_otdfctl_kasr list --sort uri:asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg prefix "https://$sort_prefix" '[.key_access_servers[] | select(.uri | startswith($prefix)) | .id] | join(",")')" "$kas_a_id,$kas_b_id,$kas_c_id"

    run_otdfctl_kasr list --sort created_at:asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$kas_a_id" --arg b "$kas_b_id" --arg c "$kas_c_id" '[.key_access_servers[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$kas_a_id,$kas_b_id,$kas_c_id"

    run_otdfctl_kasr update --id "$kas_a_id" --label sort=a --json
    assert_success
    sleep 1
    run_otdfctl_kasr update --id "$kas_b_id" --label sort=b --json
    assert_success
    sleep 1
    run_otdfctl_kasr update --id "$kas_c_id" --label sort=c --json
    assert_success

    run_otdfctl_kasr list --sort updated_at:asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$kas_a_id" --arg b "$kas_b_id" --arg c "$kas_c_id" '[.key_access_servers[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$kas_a_id,$kas_b_id,$kas_c_id"

    run_otdfctl_kasr list --sort name: --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg prefix "$sort_prefix" '[.key_access_servers[] | select((.name // "") | startswith($prefix)) | .id] | join(",")')" "$kas_c_id,$kas_b_id,$kas_a_id"

    run_otdfctl_kasr list --sort :asc --limit 500 --json
    assert_success
    assert_equal "$(echo "$output" | jq -r --arg a "$kas_a_id" --arg b "$kas_b_id" --arg c "$kas_c_id" '[.key_access_servers[] | select(.id == $a or .id == $b or .id == $c) | .id] | join(",")')" "$kas_a_id,$kas_b_id,$kas_c_id"

    run_otdfctl_kasr delete --id "$kas_a_id" --force
    run_otdfctl_kasr delete --id "$kas_b_id" --force
    run_otdfctl_kasr delete --id "$kas_c_id" --force
}
