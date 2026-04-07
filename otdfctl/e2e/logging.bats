#!/usr/bin/env bats

setup() {
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"
}

@test "version is logged to stderr when debug logging enabled" {
    run --separate-stderr -- ./otdfctl --version --log-level debug

    assert_success
    assert_output --partial "otdfctl version"
    [[ "$stderr" == *"otdfctl version"* ]]
    [[ "$stderr" == *"\"level\":\"DEBUG\""* ]]
}

@test "version is logged to stderr when debug enabled" {
    run --separate-stderr -- ./otdfctl --version --debug

    assert_success
    assert_output --partial "otdfctl version"
    [[ "$stderr" == *"otdfctl version"* ]]
    [[ "$stderr" == *"\"level\":\"DEBUG\""* ]]
}
