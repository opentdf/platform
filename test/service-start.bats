#!/usr/bin/env bats

# Tests for validating that the system is nominally running

@test "gRPC: health check is healthy" {
  run grpcurl "localhost:8080" "grpc.health.v1.Health.Check"
  echo "$output"
  [ $status = 0 ]
  [ $(jq -r .status <<<"${output}") = SERVING ]
}

@test "gRPC: reports a public key" {
  run grpcurl "localhost:8080" "kas.AccessService/PublicKey"
  echo "$output"

  # Is public key
  p=$(jq -r .publicKey <<<"${output}")
  [[ "$p" = "-----BEGIN PUBLIC KEY"-----* ]]

  # Is an RSA key
  printf '%s\n' "$p" | openssl asn1parse | grep rsaEncryption

  # Has expected kid
  kid=$(jq -er .kid <<<"${output}")
  [ -n "$kid" ]
}

@test "REST: new public key endpoint (no algorithm)" {
  run curl -s --show-error --fail-with-body "https://localhost:8080/kas/v2/kas_public_key"
  echo "output=$output"
  p=$(jq -r .publicKey <<<"${output}")

  # Is public key
  [[ "$p" = "-----BEGIN PUBLIC KEY"-----* ]]

  # Is an RSA key
  printf '%s\n' "$p" | openssl asn1parse | grep rsaEncryption

  # Has expected kid
  kid=$(jq -er .kid <<<"${output}")
  [ -n "$kid" ]
}

@test "REST: new public key endpoint (ec)" {
  run curl -s --show-error --fail-with-body "https://localhost:8080/kas/v2/kas_public_key?algorithm=ec:secp256r1"
  echo "$output"

  # Is an EC P256r1 curve
  echo "$output" | jq -r .publicKey | openssl asn1parse | grep prime256v1

  # Has kid
  kid=$(jq -er .kid <<<"${output}")
  [ -n "$kid" ]
}

@test "REST: public key endpoint (unknown algorithm)" {
  run curl -o /dev/null -s -w "%{http_code}" "https://localhost:8080/kas/v2/kas_public_key?algorithm=invalid"
  echo "$output"
  [ $output = 404 ]
}

@test "gRPC: public key endpoint (unknown algorithm)" {
  run grpcurl -d '{"algorithm":"invalid"}' "localhost:8080" "kas.AccessService/PublicKey" 
  echo "$output"
  [[ $output = *NotFound* ]]
}

@test "REST: health check endpoint" {
  run curl -s -w '%{http_code}' "https://localhost:8080/healthz"
  echo "$output"
  [ "${output: -3}" = "200" ]
  [ $(jq -r .status <<<"${output:0:-3}") = SERVING ]
}

@test "gRPC: healh check endpoint" {
  run grpcurl "localhost:8080" "grpc.health.v1.Health.Check"
  echo "$output"
  [ $status = 0 ]
  [ $(jq -r .status <<<"${output}") = SERVING ]
}

@test "GRPC-Gateway: Validate CORS" {
  run curl -X OPTIONS -v -s "https://localhost:8080/healthz" -H "Origin: https://example.com" -H "Access-Control-Request-Method: GET"
  echo "$output"
  [ $(grep -c "access-control-allow-origin: https://example.com" <<<"${output}") -eq 1 ]
  [ $(grep -c "access-control-allow-methods: GET" <<<"${output}") -eq 1 ]
  [ $(grep -c "access-control-allow-credentials: true" <<<"${output}") -eq 1 ]
}

@test "GRPC-Gateway: Reject non-accepted headers" {
  run curl -X OPTIONS -v -s "https://localhost:8080/healthz" \
    -H "Origin: https://example.com" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: X-Not-Allowed-Header"
    
  echo "$output"
  # Verify the headers are not present in the response
  [ $(grep -c "access-control-allow-origin: https://example.com" <<<"${output}") -eq 0 ]
  [ $(grep -c "access-control-allow-methods: GET" <<<"${output}") -eq 0 ]
  [ $(grep -c "access-control-allow-credentials: true" <<<"${output}") -eq 0 ]
  [ $(grep -c "access-control-max-age: 3600" <<<"${output}") -eq 0 ]
}

@test "Connect-RPC: Validate CORS" {
  run curl -X OPTIONS -v -s "https://localhost:8080/grpc.health.v1.Health/Check" -H "Origin: https://example.com" -H "Access-Control-Request-Method: GET"
  echo "$output"
  [ $(grep -c "access-control-allow-origin: https://example.com" <<<"${output}") -eq 1 ]
  [ $(grep -c "access-control-allow-methods: GET" <<<"${output}") -eq 1 ]
  [ $(grep -c "access-control-allow-credentials: true" <<<"${output}") -eq 1 ]
}

@test "Connect-RPC: Reject non-accepted headers" {
  run curl -X OPTIONS -v -s "https://localhost:8080/grpc.health.v1.Health/Check" \
    -H "Origin: https://example.com" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: X-Not-Allowed-Header"
    
  echo "$output"
  # Verify the headers are not present in the response
  [ $(grep -c "access-control-allow-origin: https://example.com" <<<"${output}") -eq 0 ]
  [ $(grep -c "access-control-allow-methods: GET" <<<"${output}") -eq 0 ]
  [ $(grep -c "access-control-allow-credentials: true" <<<"${output}") -eq 0 ]
  [ $(grep -c "access-control-max-age: 3600" <<<"${output}") -eq 0 ]
}

