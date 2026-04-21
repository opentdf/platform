#!/usr/bin/env bats

# Tests for creating and reading TDF files with various settings
# Notably, tests both 'ztdf' formats.

@test "examples: roundtrip Z-TDF with EC wrapped KAO" {
  # TODO: add subject mapping here to remove reliance on `provision fixtures`
  echo "[INFO] create a tdf3 format file"
  run go run ./examples encrypt -o sensitive-with-ec.txt.tdf --autoconfigure=false -A "ec:secp256r1" "Hello EC wrappers!"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected kid in its KAO"
  kaotype=$(jq -r '.encryptionInformation.keyAccess[0].type' <<<"${output}")
  echo "$kaotype"
  [ "$kaotype" = ec-wrapped ]

  echo "[INFO] decrypting..."
  run go run ./examples decrypt sensitive-with-ec.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello EC wrappers!"

  echo "[INFO] decrypting with EC..."
  run go run ./examples decrypt -A 'ec:secp256r1' sensitive-with-ec.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello EC wrappers!"
}

@test "examples: roundtrip Z-TDF with X-Wing wrapped KAO" {
  echo "[INFO] create a tdf3 format file"
  run go run ./examples encrypt -o sensitive-with-xwing.txt.tdf --autoconfigure=false -A "hpqt:xwing" "Hello X-Wing wrappers!"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected type in its KAO"
  kaotype=$(jq -r '.encryptionInformation.keyAccess[0].type' <<<"${output}")
  echo "kao.type=$kaotype"
  [ "$kaotype" = hybrid-wrapped ]

  kid=$(jq -r '.encryptionInformation.keyAccess[0].kid' <<<"${output}")
  echo "kao.kid=$kid"
  [ "$kid" = x1 ]

  echo "[INFO] decrypting..."
  run go run ./examples decrypt sensitive-with-xwing.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello X-Wing wrappers!"
}

@test "examples: roundtrip Z-TDF with P256+ML-KEM-768 wrapped KAO" {
  echo "[INFO] create a tdf3 format file"
  run go run ./examples encrypt -o sensitive-with-p256mlkem768.txt.tdf --autoconfigure=false -A "hpqt:secp256r1-mlkem768" "Hello P256+ML-KEM-768 wrappers!"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected type in its KAO"
  kaotype=$(jq -r '.encryptionInformation.keyAccess[0].type' <<<"${output}")
  echo "$kaotype"
  [ "$kaotype" = hybrid-wrapped ]

  kid=$(jq -r '.encryptionInformation.keyAccess[0].kid' <<<"${output}")
  echo "kao.kid=$kid"
  [ "$kid" = h1 ]

  echo "[INFO] decrypting..."
  run go run ./examples decrypt sensitive-with-p256mlkem768.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello P256+ML-KEM-768 wrappers!"
}

@test "examples: roundtrip Z-TDF with P384+ML-KEM-1024 wrapped KAO" {
  echo "[INFO] create a tdf3 format file"
  run go run ./examples encrypt -o sensitive-with-p384mlkem1024.txt.tdf --autoconfigure=false -A "hpqt:secp384r1-mlkem1024" "Hello P384+ML-KEM-1024 wrappers!"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected type in its KAO"
  kaotype=$(jq -r '.encryptionInformation.keyAccess[0].type' <<<"${output}")
  echo "$kaotype"
  [ "$kaotype" = hybrid-wrapped ]

  kid=$(jq -r '.encryptionInformation.keyAccess[0].kid' <<<"${output}")
  echo "kao.kid=$kid"
  [ "$kid" = h2 ]

  echo "[INFO] decrypting..."
  run go run ./examples decrypt sensitive-with-p384mlkem1024.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello P384+ML-KEM-1024 wrappers!"
}

@test "examples: legacy key support Z-TDF" {
  echo "[INFO] validating default key is r1"
  echo "[INFO] default key result: $(grpcurl "localhost:8080" "kas.AccessService/PublicKey")"

  [ "$(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid)" = r1 ]

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
  echo "[INFO] default key result: $(grpcurl "localhost:8080" "kas.AccessService/PublicKey")"

  [ "$(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid)" = r2 ]

  echo "[INFO] decrypting after key rotation"
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"
}

@test "examples: legacy kas and service config format support" {
  echo "[INFO] validating default key is r1"
  echo "[INFO] default key result: $(grpcurl "localhost:8080" "kas.AccessService/PublicKey")"

  [ "$(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid)" = r1 ]

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
  echo "[INFO] default key result: $(grpcurl "localhost:8080" "kas.AccessService/PublicKey")"

  [ "$(grpcurl "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid)" = r1 ]

  echo "[INFO] validating keys are correct by alg"
  [ "$(grpcurl -d '{"algorithm":"ec:secp256r1"}' "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid)" = e1 ]
  [ "$(grpcurl -d '{"algorithm":"rsa:2048"}' "localhost:8080" "kas.AccessService/PublicKey" | jq -e -r .kid)" = r1 ]

  echo "[INFO] decrypting after key rotation"
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"
}

wait_for_green() {
  limit=5
  for i in $(seq 1 $limit); do
    if [ "$(grpcurl "localhost:8080" "grpc.health.v1.Health.Check" | jq -e -r .status)" = SERVING ]; then
      return 0
    fi
    sleep 4
  done
}

downgrade_config() {
  ec_current_key=$1
  rsa_current_key=$2
  cat >opentdf.yaml <<EOF
logger:
  level: debug
  type: text
  output: stderr
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

  cat >opentdf.yaml <<EOF
logger:
  level: debug
  type: text
  output: stderr
services:
  kas:
    enabled: true
    preview:
      ec_tdf_enabled: true
      hybrid_tdf_enabled: true
      key_management: false
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
      - kid: x1
        alg: hpqt:xwing
      - kid: h1
        alg: hpqt:secp256r1-mlkem768
      - kid: h2
        alg: hpqt:secp384r1-mlkem1024
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
    key: ./keys/platform-key.p
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
        - kid: x1
          alg: hpqt:xwing
          private: kas-xwing-private.pem
          cert: kas-xwing-public.pem
        - kid: h1
          alg: hpqt:secp256r1-mlkem768
          private: kas-p256mlkem768-private.pem
          cert: kas-p256mlkem768-public.pem
        - kid: h2
          alg: hpqt:secp384r1-mlkem1024
          private: kas-p384mlkem1024-private.pem
          cert: kas-p384mlkem1024-public.pem
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
  rm -f sensitive*.tdf
}

teardown_file() {
  if [ -f opentdf-test-backup.yaml.bak ]; then
    mv opentdf-test-backup.yaml.bak opentdf.yaml
  fi
}
