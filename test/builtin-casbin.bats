#!/usr/bin/env bats

setup() {
    export GRPC_HOST=localhost
    export GRPC_PORT=8080
    if [[ -z "$TOKEN_ENDPOINT" ]]; then
      export TOKEN_ENDPOINT="http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"
    fi
}

# Helper function for debug logging
log_debug() {
    if [[ "${BATS_DEBUG:-0}" == "1" ]]; then
        echo "DEBUG($1): $2" >&3
    fi
}

# Helper function for info logging
log_info() {
    echo "INFO($1): $2" >&3
}

# Function to get access token
get_access_token() {
  local client=$1
  local secret=$2

  response=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${client}" \
    -d "client_secret=${secret}" \
    -d "grant_type=client_credentials" \
    $TOKEN_ENDPOINT)

  echo "$response" | jq -r '.access_token'
}

# Helper function to test GRPC access
grpc_test() {
    local test=$1
    local token=$2
    local service=$3
    local method=${4:-""}

    log_debug $test "Executing grpc_test:"
    log_debug $test "Service: $service"
    log_debug $test "Method: $method"
    
    if [ -n "$method" ]; then
        log_debug $test "Executing method call..."
        result=$(grpcurl -H "Authorization: Bearer $token" \
                -d '{}' \
                ${GRPC_HOST}:${GRPC_PORT} \
                "$service/$method" 2>&1)
    else
        log_debug $test "Executing service describe..."
        result=$(grpcurl -H "Authorization: Bearer $token" \
                ${GRPC_HOST}:${GRPC_PORT} \
                describe "$service" 2>&1)
    fi

    local exit_code=$?
    log_debug $test "grpcurl exit code: $exit_code"
    log_debug $test "grpcurl output: $result"

    echo "$result"
    return $exit_code
}

# Helper to check if method starts with Get or List
is_read_method() {
    local method=$1
    case "$method" in
        Get*|List*) return 0 ;;
        *) return 1 ;;
    esac
}

# Helper to check if output contains gRPC PERMISSION_DENIED
is_permission_denied() {
    local output=$1
    [[ "$output" == *"Code: PermissionDenied"* ]] || [[ "$output" == *"status-code: 7"* ]]
}

# Helper to check if method is public
is_public_endpoint() {
    local service=$1
    local method=$2
    [[ "$service" == "grpc.health.v1.Health" ]] || 
    [[ "$service" == "kas.AccessService" ]] ||
    [[ "$service" == "wellknownconfiguration.WellKnownService" ]]
}

@test "admin role should have access to all services' methods" {
    local test_name="admin_test"
    export OPENTDF_ADMIN_TOKEN=$(get_access_token "opentdf" "secret")

    services=$(grpcurl ${GRPC_HOST}:${GRPC_PORT} list )
    
    for service in $services; do
        log_info $test_name "Testing $service ($method_count methods)"
        methods=$(grpcurl ${GRPC_HOST}:${GRPC_PORT} describe "$service" | grep "rpc " | awk '{print $2}' | cut -d'(' -f1)
        
        for method in $methods; do
            echo "Testing $service/$method"
            run grpc_test "admin_test" "$OPENTDF_ADMIN_TOKEN" "$service" "$method"

            if is_permission_denied "$output"; then
                log_debug "admin_test" "Unexpected PERMISSION_DENIED for $service/$method"
                log_debug "admin_test" "Output: $output"
                false
            fi
            log_info $test_name "Verified access to $service/$method"
        done
    done
}

@test "standard role permissions check" {
    local test_name="standard_test"
    export OPENTDF_STANDARD_TOKEN=$(get_access_token "opentdf-sdk" "secret")
    # Get all methods from all services
    services=$(grpcurl ${GRPC_HOST}:${GRPC_PORT} list)
    
    for service in $services; do
        log_info $test_name "Testing $service ($method_count methods)"
        # Get all methods for the service
        methods=$(grpcurl ${GRPC_HOST}:${GRPC_PORT} describe "$service" | grep "rpc " | awk '{print $2}' | cut -d'(' -f1)
        
        for method in $methods; do
            log_debug $test_name "Testing $service/$method"
            run grpc_test $test_name "$OPENTDF_STANDARD_TOKEN" "$service" "$method"
            
            # Allow read methods for policy services (except unsafe)
            if ([[ "$service" == policy.* ]] && 
                [[ "$service" != *"unsafe"* ]] && 
                is_read_method "$method"]) || 
               [[ "$service/$method" == "authorization.AuthorizationService/GetDecisions" ]] || 
               [[ "$service/$method" == "authorization.AuthorizationService/GetDecisionsByToken" ]]; then
                if is_permission_denied "$output"; then
                    log_debug $test_name "Unexpected access denial for $service/$method"
                    log_debug $test_name "Output: $output"
                    false
                fi
                log_info $test_name "Verified access to $service/$method"
            # Deny everything else except public endpoints
            else
                if is_public_endpoint "$service" "$method"; then
                    log_info $test_name "Verified public endpoint $service/$method"
                elif ! is_permission_denied "$output"; then
                    log_debug $test_name "Expected access denial for $service/$method"
                    log_debug $test_name "Output: $output"
                    false
                else
                    log_info $test_name "Verified access denial for $service/$method"
                fi
            fi
        done
    done
}