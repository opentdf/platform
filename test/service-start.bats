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
  [ $(jq -r .kid <<<"${output}") = r1 ]
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

@test "HTTP: Validate CORS" {
  run curl -X OPTIONS -v -s "https://localhost:8080/healthz" -H "Origin: https://example.com" -H "Access-Control-Request-Method: GET"
  echo "$output"
  [ $(grep -c "access-control-allow-origin: https://example.com" <<<"${output}") -eq 1 ]
  [ $(grep -c "access-control-allow-methods: GET" <<<"${output}") -eq 1 ]
  [ $(grep -c "access-control-allow-credentials: true" <<<"${output}") -eq 1 ]
}

@test "HTTP: Reject non-accepted headers" {
  run curl -X OPTIONS -v -s "https://localhost:8080/healthz" \
    -H "Origin: https://example.com" \
    -H "Access-Control-Request-Method: GET" \

    
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

