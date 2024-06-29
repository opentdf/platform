#!/usr/bin/env bats

# Set up environment variables or any required setup
setup() {
  if [ -z "$BATS_LIB_PATH" ]; then
    BATS_LIB_PATH="/usr"
  fi
  load "${BATS_LIB_PATH}/lib/bats-support/load.bash"
  load "${BATS_LIB_PATH}/lib/bats-assert/load.bash"
  export BASE_URL="localhost:8080"
  export CLIENT_ID="opentdf"
  export CLIENT_SECRET="secret"
  export TOKEN_ENDPOINT="http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"
}

@test "Get client's credentials and call AuthorizationService.GetEntitlements" {
  # Step 1: Get client's credentials
  run curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    $TOKEN_ENDPOINT

  assert_success
  assert_output --partial "access_token"

  # Debug: Print the output to check for issues
  echo "Token Endpoint Response: $output"

  # Extract the access token from the response
  ACCESS_TOKEN=$(echo "$output" | jq -r '.access_token')
  echo "Access Token: $ACCESS_TOKEN"
  assert [ -n "$ACCESS_TOKEN" ]

  # Step 2: Call AuthorizationService.GetEntitlements
  JSON_BODY=$(cat <<EOF
{
  "entities": [
    {
      "id": "custom-rego",
      "client_id": "opentdf"
    }
  ]
}
EOF
)

  echo "Using Access Token: $ACCESS_TOKEN"

  # Print the grpcurl command for debugging
  echo grpcurl -plaintext -H \"Authorization: Bearer $ACCESS_TOKEN\" -d \"$JSON_BODY\" $BASE_URL authorization.AuthorizationService/GetEntitlements

  run grpcurl -plaintext -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d "$JSON_BODY" \
    $BASE_URL authorization.AuthorizationService/GetEntitlements

  assert_success
  assert_output --partial "https://example.net/attr/attr1/value/value1"
  assert_output --partial "https://opentdf.io/attr/role/value/developer"
  assert_output --partial "\"entityId\": \"custom-rego\""

  # Debug: Print the output to check for issues
  echo "GetEntitlements Response: $output"
}
