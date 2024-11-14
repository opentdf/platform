#!/usr/bin/env bats

# Tests for creating and reading TDF files with various settings
# Notably, tests both 'ztdf' and 'nano' formats.

@test "examples: roundtrip Z-TDF" {
  # TODO: add subject mapping here to remove reliance on `provision fixtures`
  echo "[INFO] configure attribute with grant for local kas"
  go run ./examples --creds opentdf:secret kas add --kas http://localhost:8080 --public-key "$(<${BATS_TEST_DIRNAME}/../kas-cert.pem)"
  go run ./examples --creds opentdf:secret attributes unassign -a https://example.com/attr/attr1 -v value1
  go run ./examples --creds opentdf:secret attributes unassign -a https://example.com/attr/attr1
  go run ./examples --creds opentdf:secret attributes assign -a https://example.com/attr/attr1 -v value1 -k http://localhost:8080

  echo "[INFO] create a tdf3 format file"
  run go run ./examples encrypt "Hello Zero Trust"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected kid in its KAO"
  kid=$(jq -r '.encryptionInformation.keyAccess[0].kid' <<<"${output}")
  echo "$kid"
  [ $kid = r1 ]

  echo "[INFO] decrypting..."
  run go run ./examples decrypt sensitive.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello Zero Trust"
}

@test "examples: roundtrip Z-TDF with extra unnecessary, invalid kas" {
  # TODO: add subject mapping here to remove reliance on `provision fixtures`
  echo "[INFO] configure attribute with grant for local kas"
  go run ./examples --creds opentdf:secret kas add --kas http://localhost:8080 --public-key "$(<${BATS_TEST_DIRNAME}/../kas-cert.pem)"
  go run ./examples --creds opentdf:secret kas add --kas http://localhost:9090 --algorithm "rsa:2048" --kid r2 --public-key "$(<${BATS_TEST_DIRNAME}/../kas-cert.pem)"
  go run ./examples --creds opentdf:secret attributes unassign -a https://example.com/attr/attr1 -v value1
  go run ./examples --creds opentdf:secret attributes unassign -a https://example.com/attr/attr1
  go run ./examples --creds opentdf:secret attributes assign -a https://example.com/attr/attr1 -v value1 -k "http://localhost:8080,http://localhost:9090"

  echo "[INFO] create a tdf3 format file"
  run go run ./examples encrypt "Hello multikao split"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected kid in its KAO"
  u1=$(jq -r '.encryptionInformation.keyAccess[0].url' <<<"${output}")
  u2=$(jq -r '.encryptionInformation.keyAccess[1].url' <<<"${output}")
  sid1=$(jq -r '.encryptionInformation.keyAccess[0].sid' <<<"${output}")
  sid2=$(jq -r '.encryptionInformation.keyAccess[1].sid' <<<"${output}")
  echo "${u1},${sid1} ?= ${u2},${sid2}"
  [ $u1 != $u2 ]
  [ $sid1 = $sid2 ]

  echo "[INFO] decrypting..."
  run go run ./examples decrypt sensitive.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello multikao split"
}

@test "examples: roundtrip nanoTDF" {
  echo "[INFO] creating nanotdf file"
  go run ./examples encrypt -o sensitive.txt.ntdf --nano --no-kid-in-nano "Hello NanoTDF"
  go run ./examples encrypt -o sensitive-kid.txt.ntdf --nano "Hello NanoTDF KID"

  echo "[INFO] decrypting nanotdf..."
  go run ./examples decrypt sensitive.txt.ntdf
  go run ./examples decrypt sensitive.txt.ntdf | grep "Hello NanoTDF"
  go run ./examples decrypt sensitive-kid.txt.ntdf
  go run ./examples decrypt sensitive-kid.txt.ntdf | grep "Hello NanoTDF KID"
}

@test "examples: legacy key support Z-TDF" {
  echo "[INFO] validating default key is r1"
  [ $(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid) = r1 ]

  echo "[INFO] encrypting samples"
  go run ./examples encrypt --autoconfigure=false -o sensitive-with-no-kid.txt.tdf --no-kid-in-kao "Hello Legacy"
  go run ./examples encrypt --autoconfigure=false -o sensitive-with-kid.txt.tdf "Hello with Key Identifier"

  echo "[INFO] decrypting..."
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"

  echo "[INFO] rotating keys"
  update_config e2 e1 r2 r1
  sleep 4
  wait_for_green

  echo "[INFO] validating default key is r2"
  [ $(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid) = r2 ]

  echo "[INFO] decrypting after key rotation"
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"
}

@test "examples: legacy kas and service config format support" {
  echo "[INFO] validating default key is r1"
  [ $(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid) = r1 ]

  echo "[INFO] encrypting samples"
  go run ./examples encrypt --autoconfigure=false -o sensitive-with-no-kid.txt.tdf --no-kid-in-kao "Hello Legacy"
  go run ./examples encrypt --autoconfigure=false -o sensitive-with-kid.txt.tdf "Hello with Key Identifier"

  echo "[INFO] decrypting..."
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"

  echo "[INFO] downgrading"
  downgrade_config e1 r1
  sleep 4
  wait_for_green

  echo "[INFO] validating default key is r1"
  [ $(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid) = r1 ]

  echo "[INFO] decrypting after key rotation"
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"
}


wait_for_green() {
  limit=5
  for i in $(seq 1 $limit); do
    if [ $(grpcurl "localhost:8080" "grpc.health.v1.Health.Check" | jq -e -r .status) = SERVING ]; then
      return 0
    fi
    sleep 4
  done
}

downgrade_config() {
  ec_current_key=$1
  rsa_current_key=$2
  cat >opentdf.yaml<<EOF
logger:
  level: debug
  type: text
  output: stdout
services:
  kas:
    enabled: true
    eccertid: ${ec_current_key}
    rsacertid: ${rsa_current_key}
  policy:
    enabled: true
  authorization:
    enabled: true
    ersurl: http://localhost:8080/entityresolution/resolve
    clientid: tdf-authorization-svc
    clientsecret: secret
    tokenendpoint: http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token
  entityresolution:
    enabled: true
    url: http://localhost:8888/auth
    clientid: "tdf-entity-resolution"
    clientsecret: "secret"
    realm: "opentdf"
    legacykeycloak: true
server:
  tls:
    enabled: true
    cert: ./keys/platform.crt
    key: ./keys/platform-key.pem
  auth:
    enabled: true
    enforceDPoP: false
    audience: "http://localhost:8080"
    issuer: http://localhost:8888/auth/realms/opentdf
  cors:
    enabled: false
  cryptoProvider:
    type: standard
    standard:
      rsa:
        r1:
          private_key_path: kas-private.pem
          public_key_path: kas-cert.pem
        r2:
          private_key_path: kas-r2-private.pem
          public_key_path: kas-r2-cert.pem
      ec:
        e1:
          private_key_path: kas-ec-private.pem
          public_key_path: kas-ec-cert.pem
        e2:
          private_key_path: kas-e2-private.pem
          public_key_path: kas-e2-cert.pem
  port: 8080
opa:
  embedded: true
EOF
}

update_config() {
  ec_current_key=$1
  ec_legacy_key=$2
  rsa_current_key=$3
  rsa_legacy_key=$4

  cat >opentdf.yaml<<EOF
logger:
  level: debug
  type: text
  output: stdout
services:
  kas:
    enabled: true
    keyring:
      - kid: ${ec_current_key}
        alg: ec:secp256r1
      - kid: ${ec_legacy_key}
        alg: ec:secp256r1
        legacy: true
      - kid: ${rsa_current_key}
        alg: rsa:2048
      - kid: ${rsa_legacy_key}
        alg: rsa:2048
        legacy: true
  policy:
    enabled: true
  authorization:
    enabled: true
    ersurl: http://localhost:8080/entityresolution/resolve
    clientid: tdf-authorization-svc
    clientsecret: secret
    tokenendpoint: http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token
  entityresolution:
    enabled: true
    url: http://localhost:8888/auth
    clientid: "tdf-entity-resolution"
    clientsecret: "secret"
    realm: "opentdf"
    legacykeycloak: true
server:
  tls:
    enabled: true
    cert: ./keys/platform.crt
    key: ./keys/platform-key.pem
  auth:
    enabled: true
    enforceDPoP: false
    audience: "http://localhost:8080"
    issuer: http://localhost:8888/auth/realms/opentdf
  cors:
    enabled: false
  cryptoProvider:
    type: standard
    standard:
      keys:
        - kid: r2
          alg: rsa:2048
          private: kas-r2-private.pem
          cert: kas-r2-cert.pem
        - kid: e2
          alg: ec:secp256r1
          private: kas-e2-private.pem
          cert: kas-e2-cert.pem
        - kid: r1
          alg: rsa:2048
          private: kas-private.pem
          cert: kas-cert.pem
        - kid: e1
          alg: ec:secp256r1
          private: kas-ec-private.pem
          cert: kas-ec-cert.pem
  port: 8080
opa:
  embedded: true
EOF
}

setup_file() {
  if [ -f opentdf.yaml ]; then
    cp opentdf.yaml opentdf-test-backup.yaml.bak
  fi
  openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-r2-private.pem -out kas-r2-cert.pem -days 365
  openssl ecparam -name prime256v1 >ecparams.tmp
  openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout kas-e2-private.pem -out kas-e2-cert.pem -days 365
}

setup() {
  update_config e1 e1 r1 r1
  sleep 4
  wait_for_green
}

teardown() {
  rm -f sensitive*.txt.n?tdf
}

teardown_file() {
  if [ -f opentdf-test-backup.yaml.bak ]; then
    mv opentdf-test-backup.yaml.bak opentdf.yaml
  fi
}
