#!/usr/bin/env bats

# Set up environment variables or any required setup
setup() {
  export BATS_LIB_PATH="${BATS_LIB_PATH}:/usr/lib"
  bats_load_library bats-support
  bats_load_library bats-assert
  bats_load_library bats-file
  bats_load_library bats-detik/detik.bash
  export BASE_URL="localhost:8080"
  export CLIENT_ID="opentdf"
  export CLIENT_SECRET="secret"
  export TOKEN_ENDPOINT="http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"
}

# Function to get access token
get_access_token() {
  response=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    $TOKEN_ENDPOINT)

  echo "$response" | jq -r '.access_token'
}

@test "Get client's credentials and call AuthorizationService.GetEntitlements" {
  # Get access token
  ACCESS_TOKEN=$(get_access_token)
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
  assert_output --partial "https://scenario.com/attr/working_group/value/blue"
  assert_output --partial "https://example.com/attr/attr1/value/value1"
  assert_output --partial "https://example.net/attr/attr1/value/value1"
  assert_output --partial "\"entityId\": \"custom-rego\""

  # Debug: Print the output to check for issues
  echo "GetEntitlements Response: $output"
}
