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

@test "gRPC: kas grants assignment" {
  go run ./examples --creds opentdf:secret kas add --kas https://a.example.io --public-key "$(<${BATS_TEST_DIRNAME}/../kas-cert.pem)"
  go run ./examples --creds opentdf:secret kas add --kas https://b.example.io --public-key "$(<${BATS_TEST_DIRNAME}/../kas-cert.pem)"
  go run ./examples --creds opentdf:secret kas add --kas https://c.example.io --public-key "$(<${BATS_TEST_DIRNAME}/../kas-cert.pem)"

  run go run ./examples --creds opentdf:secret kas ls -l
  echo "$output"
  [[ $output = *"https://a.example.io"* ]]
  [[ $output = *"https://b.example.io"* ]]
  [[ $output = *"https://c.example.io"* ]]
  [ $status = 0 ]

  go run ./examples --creds opentdf:secret attributes add -a https://grant.example.io/attr/test -v "a b c"

  go run ./examples --creds opentdf:secret attributes assign -a https://grant.example.io/attr/test -v a -k https://a.example.io
  go run ./examples --creds opentdf:secret attributes assign -a https://grant.example.io/attr/test -v b -k https://b.example.io
  go run ./examples --creds opentdf:secret attributes assign -a https://grant.example.io/attr/test -v c -k https://c.example.io

  go run ./examples --creds opentdf:secret kas rm -k https://a.example.io
  go run ./examples --creds opentdf:secret kas rm -k https://b.example.io
  go run ./examples --creds opentdf:secret kas rm -k https://c.example.io

  run go run ./examples --creds opentdf:secret attributes rm -f -a https://grant.example.io/attr/test
  echo "$output"
  [[ $output = *"deleted attribute"* ]]
  [ $status = 0 ]
}
