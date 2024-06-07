#!/usr/bin/env bats

@test "gRPC: lists attributes" {
 grpcurl -plaintext localhost:8080 list
}

@test "gRPC: health check is healthy" {
  grpcurl -plaintext localhost:8080 grpc.health.v1.Health.Check
}

@test "gRPC: reports a public key" {
  grpcurl -plaintext localhost:8080 kas.AccessService/PublicKey
}

@test "REST: new public key endpoint (no algorithm)" {
  curl --show-error --fail-with-body --insecure localhost:8080/kas/v2/kas_public_key
}

@test "REST: new public key endpoint (ec)" {
  curl --show-error --fail-with-body --insecure localhost:8080/kas/v2/kas_public_key?algorithm=ec:secp256r1
  # TODO: replace with jq and exact query to avoid false negatives
  curl --show-error --fail-with-body --insecure localhost:8080/kas/v2/kas_public_key?algorithm=ec:secp256r1 | grep e1
}

@test "REST: public key endpoint (unknown algorithm)" {
  curl_status=$(curl -o /dev/null -s -w "%{http_code}" localhost:8080/kas/v2/kas_public_key?algorithm=invalid)
  [ $curl_status = 404 ]
}

@test "gRPC: public key endpoint (unknown algorithm)" {
  grpcurl -d '{"algorithm":"invalid"}' -plaintext localhost:8080 kas.AccessService/PublicKey  2>&1  | grep NotFound
}

@test "examples: roundtrip" {
  go run ./examples encrypt "Hello Virtru"
  go run ./examples decrypt sensitive.txt.tdf
  go run ./examples decrypt sensitive.txt.tdf | grep "Hello Virtru"
}
