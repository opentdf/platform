#!/usr/bin/env bats

wait_for_green() {
  limit=5
  for i in $(seq 1 $limit); do
    if [ $(grpcurl -plaintext "localhost:8080" "grpc.health.v1.Health.Check" | jq -e -r .status) = SERVING ]; then
      return 0
    fi
    sleep 4
  done
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
# DB and Server configurations are defaulted for local development
# db:
#   host: localhost
#   port: 5432
#   user: postgres
#   password: changeme
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
  auth:
    enabled: true
    enforceDPoP: false
    audience: "http://localhost:8080"
    issuer: http://localhost:8888/auth/realms/opentdf
    policy:
      ## Default policy for all requests
      default: #"role:standard"
      ## Dot notation is used to access nested claims (i.e. realm_access.roles)
      claim: # realm_access.roles
      ## Maps the external role to the opentdf role
      ## Note: left side is used in the policy, right side is the external role
      map:
        # standard: opentdf-standard
        # admin: opentdf-admin
        # org-admin: opentdf-org-admin

      ## Custom policy (see examples https://github.com/casbin/casbin/tree/master/examples)
      csv: #|
      #  p, role:org-admin, policy:attributes, *, *, allow
      #  p, role:org-admin, policy:subject-mappings, *, *, allow
      #  p, role:org-admin, policy:resource-mappings, *, *, allow
      #  p, role:org-admin, policy:kas-registry, *, *, allow

      ## Custom model (see https://casbin.org/docs/syntax-for-models/)
      model: #|
      #  [request_definition]
      #  r = sub, res, act, obj
      #
      #  [policy_definition]
      #  p = sub, res, act, obj, eft
      #
      #  [role_definition]
      #  g = _, _
      #
      #  [policy_effect]
      #  e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
      #
      #  [matchers]
      #  m = g(r.sub, p.sub) && globOrRegexMatch(r.res, p.res) && globOrRegexMatch(r.act, p.act) && globOrRegexMatch(r.obj, p.obj)
  cors:
    enabled: false
    # '*' to allow any origin or a specific domain like 'https://yourdomain.com'
    allowedorigins: 
      - "*"
    # List of methods. Examples: 'GET,POST,PUT'
    allowedmethods:
      - GET
      - POST
      - PATCH
      - PUT
      - DELETE
      - OPTIONS
    # List of headers that are allowed in a request
    allowedheaders:
      - ACCEPT
      - Authorization
      - Content-Type
      - X-CSRF-Token
    # List of response headers that browsers are allowed to access
    exposedheaders:
      - Link
    # Sets whether credentials are included in the CORS request
    allowcredentials: true
    # Sets the maximum age (in seconds) of a specific CORS preflight request
    maxage: 3600
  grpc:
    reflectionEnabled: true # Default is false
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
  embedded: true # Only for local development
EOF
}

setup_file() {
  if [ -f opentdf.yaml ]; then
    mv opentdf.yaml opentdf-test-backup.yaml.bak
  fi
  openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-r2-private.pem -out kas-r2-cert.pem -days 365
  openssl ecparam -name prime256v1 >ecparams.tmp
  openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout kas-e2-private.pem -out kas-e2-cert.pem -days 365

  update_config e1 e1 r1 r1
  sleep 4
  wait_for_green
}

teardown_file() {
  if [ -f opentdf-test-backup.yaml.bak ]; then
    mv opentdf-test-backup.yaml opentdf.yaml
  fi
}

@test "examples: roundtrip Z-TDF" {
  run go run ./examples encrypt "Hello Zero Trust"
  echo "$output"


  # Has expected kid
  kid=$(jq -r '.encryptionInformation.keyAccess[0].kid' <<<"${output}")
  echo "$kid"
  [ $kid = r2 ]

  # decrypts properly
  run go run ./examples decrypt sensitive.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello Zero Trust"
}

@test "examples: roundtrip nanoTDF" {
  go run ./examples encrypt -o sensitive.txt.ntdf --nano "Hello NanoTDF"
  go run ./examples decrypt sensitive.txt.ntdf
  go run ./examples decrypt sensitive.txt.ntdf | grep "Hello NanoTDF"
}

# bats test_tags=bats:focus
@test "examples: legacy key support Z-TDF" {
  echo [INFO] encrypting samples
  go run ./examples encrypt -o sensitive-with-no-kid.txt.tdf --no-kid-in-kao "Hello Legacy"
  go run ./examples encrypt -o sensitive-with-kid.txt.tdf "Hello with Key Identifier"

  echo [INFO] decrypting...
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"

  echo [INFO] rotating keys
  update_config e2 e1 r2 r1
  sleep 4
  wait_for_green

  echo [INFO] decrypting after key rotation
  go run ./examples decrypt sensitive-with-no-kid.txt.tdf | grep "Hello Legacy"
  go run ./examples decrypt sensitive-with-kid.txt.tdf | grep "Hello with Key Identifier"
}

teardown() {
  rm -f sensitive*.txt.n?tdf
}
