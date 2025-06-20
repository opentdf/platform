#!/usr/bin/env bats

# Tests for policy service administration

@test "gRPC: lists attributes" {
  run grpcurl "localhost:8080" list
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

  run go run ./examples --creds opentdf:secret attributes add -a https://example.io/attr/IntellectualProperty -v "TradeSecret,Proprietary,BusinessSensitive,Open" --rule hierarchy
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

@test "gRPC: kas registry update and remove" {
  run go run ./examples --creds opentdf:secret kas ls
  echo "$output"
  [[ $output = *"listing kas registry"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret kas add -k https://example.io
  echo "$output"
  [[ $output = *"registered kas"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret kas add -k https://example.io --public-key MY_PUBLIC_KEY --kid my-public-key --algorithm rsa:2048
  echo "$output"
  [[ $output = *"registered kas"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret kas ls
  echo "$output"
  [[ $output = *"https://example.io"* ]]
  [ $status = 0 ]

  run go run ./examples --creds opentdf:secret kas rm -k https://example.io
  echo "$output"
  [[ $output = *"deleted kas registration"* ]]
  [ $status = 0 ]
}
