#!/usr/bin/env bats

# Tests for policy service administration

@test "gRPC: lists attributes" {
  run grpcurl -plaintext "localhost:8080" list
  echo "$output"
  [ $status = 0 ]
  [[ $output = *grpc.health.v1.Health* ]]
  [[ $output = *wellknownconfiguration.WellKnownService* ]]
}

@test "gRPC: attributes configure" {
  run go run ./examples --creds opentdf:secret attributes ls
  echo "$output"
  [[ $output = *"listing namespaces"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret attributes add -a https://example.io/attr/IntellectualProperty -v "TradeSecret Proprietary BusinessSensitive Open" --rule hierarchy 
  echo "$output"
  [[ $output = *"created attribute"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret attributes ls
  echo "$output"
  [[ $output = *"businesssensitive"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret attributes rm -f -a https://example.io/attr/IntellectualProperty
  echo "$output"
  [[ $output = *"deleted attribute"* ]]
  [ $status = 0 ]
}
