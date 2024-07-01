#!/usr/bin/env bats

# Tests for validating that the system is nominally running

setup() {
    bats_load_library bats-support
    bats_load_library bats-assert
}

@test "gRPC: lists attributes" {
  run grpcurl -plaintext "localhost:8080" list
  assert_success
  assert_line grpc.health.v1.Health
  assert_line wellknownconfiguration.WellKnownService
}

@test "gRPC: health check is healthy" {
  run grpcurl -plaintext "localhost:8080" "grpc.health.v1.Health.Check"
  assert_success
  assert_output --partial SERVING

  run jq -r .status <<<${output}
  assert_equal "${output}" SERVING
}

@test "gRPC: reports a public key" {
  run grpcurl -plaintext "localhost:8080" "kas.AccessService/PublicKey"

  # Has expected kid
  assert_equal "$(jq -r .kid <<<"${output}")" r1

  # Is public key
  assert_output --partial PUBLIC

  run jq -r .publicKey <<<"${output}"
  assert_regex "$output" "^-----BEGIN PUBLIC KEY-----"

  # Is an RSA key
  run openssl asn1parse <<<$output
  assert_line --partial rsaEncryption
}

@test "REST: new public key endpoint (no algorithm)" {
  run curl -s --show-error --fail-with-body --insecure "localhost:8080/kas/v2/kas_public_key"

  # Has expected kid
  assert_equal "$(jq -r .kid <<<"${output}")" r1

  run jq -r .publicKey <<<"${output}"
  assert_regex "$output" "^-----BEGIN PUBLIC KEY-----"

  # Is an RSA key
  run openssl asn1parse <<<$output
  assert_line --partial rsaEncryption
}

@test "REST: new public key endpoint (ec)" {
  run curl -s --show-error --fail-with-body --insecure "localhost:8080/kas/v2/kas_public_key?algorithm=ec:secp256r1"

  # Has expected kid
  assert_equal "$(jq -r .kid <<<"${output}")" e1

  run jq -r .publicKey <<<"${output}"
  assert_regex "$output" "^-----BEGIN PUBLIC KEY-----"

  # Is an EC P256r1 curve
  run openssl asn1parse <<<$output
  assert_line --partial prime256v1
}

@test "REST: public key endpoint (unknown algorithm)" {
  run curl -o /dev/null -s -w "%{http_code}" "localhost:8080/kas/v2/kas_public_key?algorithm=invalid"
  assert_output 404
}

@test "gRPC: public key endpoint (unknown algorithm)" {
  run grpcurl -d '{"algorithm":"invalid"}' -plaintext "localhost:8080" "kas.AccessService/PublicKey" 
  assert_output --partial NotFound
}
