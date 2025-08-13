#!/usr/bin/env bats

# Tests for validating that we are using a vault backend

@test "vault: service is available" {
    run vault status
    echo "${output}"
    [ $status = 0 ]
}

@test "vault: we can log in as an approle" {
    . ./setup-vault-env.sh
    echo "$KAS_ADMIN_TOKEN" | vault login -
    run vault kv list -mount=secret kas_keypair
    echo "${output}"
    [ $status = 0 ]
}

@test "vault: we can add new keys (rotate)" {
    . ./setup-vault-env.sh
    run ./new-keys.sh
    echo "${output}"
    [ $status = 0 ]
}
