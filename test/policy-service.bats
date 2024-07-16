#!/usr/bin/env bats

# Tests for policy service administration

@test "gRPC: lists attributes" {
  run grpcurl -plaintext "localhost:8080" list
  echo "$output"
  [ $status = 0 ]
  [[ $output = *grpc.health.v1.Health* ]]
  [[ $output = *wellknownconfiguration.WellKnownService* ]]
}

@test "gRPC: attributes example" {
  run go run ./examples --creds opentdf:secret attributes
  echo "$output"
  [[ $output = *"listing namespaces"* ]]
  [ $status = 0 ]
}
