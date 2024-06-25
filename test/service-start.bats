#!/usr/bin/env bats

# Tests for validating that the system is nominally running

@test "gRPC: lists attributes" {
  run grpcurl -plaintext "localhost:8080" list
  echo "$output"
  [ $status = 0 ]
  [[ $output = *grpc.health.v1.Health* ]]
  [[ $output = *wellknownconfiguration.WellKnownService* ]]
}

@test "gRPC: health check is healthy" {
  run grpcurl -plaintext "localhost:8080" "grpc.health.v1.Health.Check"
  echo "$output"
  [ $status = 0 ]
  [ $(jq -r .status <<<"${output}") = SERVING ]
}

@test "gRPC: reports a public key" {
  run grpcurl -plaintext "localhost:8080" "kas.AccessService/PublicKey"
  echo "$output"

  # Is public key
  p=$(jq -r .publicKey <<<"${output}")
  [[ "$p" = "-----BEGIN PUBLIC KEY"-----* ]]

  # Is an RSA key
  printf '%s\n' "$p" | openssl asn1parse | grep rsaEncryption

  # Has expected kid
  [ $(jq -r .kid <<<"${output}") = r1 ]
}

@test "REST: new public key endpoint (no algorithm)" {
  run curl -s --show-error --fail-with-body --insecure "localhost:8080/kas/v2/kas_public_key"
  echo "output=$output"
  p=$(jq -r .publicKey <<<"${output}")

  # Is public key
  [[ "$p" = "-----BEGIN PUBLIC KEY"-----* ]]

  # Is an RSA key
  printf '%s\n' "$p" | openssl asn1parse | grep rsaEncryption

  # Has expected kid
  [ $(jq -r .kid <<<"${output}") = r1 ]
}

@test "REST: new public key endpoint (ec)" {
  run curl -s --show-error --fail-with-body --insecure "localhost:8080/kas/v2/kas_public_key?algorithm=ec:secp256r1"
  echo "$output"

  # Is public key
  p=$(jq -r .publicKey <<<"${output}")
  [[ "$p" = "-----BEGIN PUBLIC KEY"-----* ]]

  # Is an EC P256r1 curve
  printf '%s\n' "$p" | openssl asn1parse | grep prime256v1

  # Has expected kid
  [ $(jq -r .kid <<<"${output}") = e1 ]
}

@test "REST: public key endpoint (unknown algorithm)" {
  run curl -o /dev/null -s -w "%{http_code}" "localhost:8080/kas/v2/kas_public_key?algorithm=invalid"
  echo "$output"
  [ $output = 404 ]
}

@test "gRPC: public key endpoint (unknown algorithm)" {
  run grpcurl -d '{"algorithm":"invalid"}' -plaintext "localhost:8080" "kas.AccessService/PublicKey" 
  echo "$output"
  [[ $output = *NotFound* ]]
}
