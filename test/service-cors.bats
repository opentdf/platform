#!/usr/bin/env bats

# Tests for validating CORS configuration allows Authorization header

@test "CORS: preflight request includes Authorization in allowed headers" {
  run curl -i -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: authorization,content-type,connect-protocol-version" \
    http://localhost:8080/policy.namespaces.NamespaceService/GetNamespace

  echo "$output"

  # Verify 200 OK response
  [[ "$output" =~ "HTTP/1.1 200 OK" ]]

  # Verify Access-Control-Allow-Headers includes Authorization
  [[ "$output" =~ "Access-Control-Allow-Headers:".*"Authorization" ]]

  # Verify Access-Control-Allow-Origin is set
  [[ "$output" =~ "Access-Control-Allow-Origin: http://localhost:3000" ]]

  # Verify credentials are allowed
  [[ "$output" =~ "Access-Control-Allow-Credentials: true" ]]

  # Verify max-age is set
  [[ "$output" =~ "Access-Control-Max-Age: 3600" ]]
}

@test "CORS: preflight request with different headers" {
  run curl -i -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: authorization" \
    http://localhost:8080/policy.namespaces.NamespaceService/GetNamespace

  echo "$output"

  # Verify 200 OK response
  [[ "$output" =~ "HTTP/1.1 200 OK" ]]

  # Verify Authorization is in allowed headers
  [[ "$output" =~ "Access-Control-Allow-Headers:".*"Authorization" ]]
}

@test "CORS: actual request with Authorization header" {
  run curl -i -X POST \
    -H "Origin: http://localhost:3000" \
    -H "Authorization: Bearer test-token" \
    -H "Content-Type: application/json" \
    -H "Connect-Protocol-Version: 1" \
    http://localhost:8080/policy.namespaces.NamespaceService/GetNamespace

  echo "$output"

  # Verify CORS headers are in response (status may be 401 due to invalid token, but CORS should work)
  [[ "$output" =~ "Access-Control-Allow-Origin: http://localhost:3000" ]]
  [[ "$output" =~ "Access-Control-Allow-Credentials: true" ]]
}

@test "CORS: wildcard origin configuration" {
  run curl -i -X OPTIONS \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: authorization,content-type" \
    http://localhost:8080/policy.namespaces.NamespaceService/GetNamespace

  echo "$output"

  # With wildcard ("*") in config, different origins should work
  # Server should return 200 OK
  [[ "$output" =~ "HTTP/1.1 200 OK" ]]

  # Origin should be reflected back or wildcard
  [[ "$output" =~ "Access-Control-Allow-Origin:" ]]
}

@test "CORS: verify Content-Type in allowed headers" {
  run curl -i -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: content-type" \
    http://localhost:8080/policy.namespaces.NamespaceService/GetNamespace

  echo "$output"

  # Verify Content-Type is in allowed headers
  [[ "$output" =~ "Access-Control-Allow-Headers:".*"Content-Type" ]]
}

@test "CORS: verify Connect-Protocol-Version in allowed headers" {
  run curl -i -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: connect-protocol-version" \
    http://localhost:8080/policy.namespaces.NamespaceService/GetNamespace

  echo "$output"

  # Verify Connect-Protocol-Version is in allowed headers
  [[ "$output" =~ "Access-Control-Allow-Headers:".*"Connect-Protocol-Version" ]]
}
