# Obligations Decisioning BDD Tests

## ✅ Current Status

- **Smoke Test (@smoke-obligations)**: ✅ **FULLY WORKING** - 1 scenario, 19 steps, all passing
- **Full Test Suite (@obligations)**: ⚠️ **Requires Authorization v2 API** (currently only available in DEBUG mode)

## Overview

Comprehensive end-to-end BDD tests for the obligations decisioning feature, covering all acceptance criteria from the JIRA requirements.

**IMPORTANT**: These tests require the **Authorization v2 API** which supports obligations. As of now:
- ✅ **DEBUG mode** (inline platform): Uses v2 API - **ALL TESTS WORK**
- ⚠️ **Containerized mode**: May use v1 API - Only tests that don't require obligations work
- 🔄 Once the platform container is updated to use v2 API, all tests will work in containerized mode

## Test Files

### Feature Files
- **`features/obligations-basic.feature`** - Simple smoke test (single scenario, ~20 steps)
  - Creates obligation with value
  - Sets up trigger for action on attribute value
  - Creates subject mapping for authorization
  - Verifies obligation appears in decision response
  - ✅ **PASSES in DEBUG mode** - Full e2e obligations validation

- **`features/obligations.feature`** - Comprehensive test suite (8 scenarios, ~190 steps)
  - Obligation definition and values
  - Triggers with client ID scoping
  - Multi-resource decisions
  - Entity chain obligations
  - ABAC scenarios with obligations
  - Multiple obligations on single resource
  - Negative cases (no trigger, mismatched action)
  - ⚠️ **DEBUG mode only** - Each scenario needs isolated platform instance

### Step Definitions
- **`cukes/steps_obligations.go`** - Obligations-specific steps (12 functions)
  - Create obligations and values
  - Create obligation triggers
  - Verify obligations in decision responses
  
- **`cukes/steps_authorization.go`** - Authorization v2 API integration
  - **Uses Authorization v2 API** (required for obligations support)
  - Creates entity chains
  - Sends decision requests with fulfillable obligations
  - Validates decision responses
  
- **`cukes/steps_subjectmappings.go`** - ABAC setup
  - Creates condition groups and subject sets
  - Creates subject mappings for authorization

### Resources
- **`cukes/resources/keycloak_obligations.template`** - Keycloak realm configuration
  - Pre-configured users: alice (TS clearance), bob (S clearance), charlie (C clearance)
  - Used for ABAC testing with user attributes

## Running the Tests

### ✅ Recommended: Single Scenario in DEBUG Mode

The **obligations basic smoke test** is fully functional and demonstrates complete e2e obligations:

```bash
# Run the basic smoke test (RECOMMENDED)
PLATFORM_IMAGE=DEBUG CUKES_LOG_HANDLER=console go test ./tests-bdd/platform_test.go -v \
  --tags=cukes \
  --godog.tags="@smoke-obligations"
```

This test:
- Creates an obligation with values
- Sets up a trigger for an action on an attribute value  
- Creates users with attributes via Keycloak
- Sets up ABAC subject mappings
- Sends a decision request
- ✅ Verifies obligations appear in the response

### Individual Scenarios (DEBUG Mode)

Run specific scenarios by line number:

```bash
# Run scenario starting at line 43
PLATFORM_IMAGE=DEBUG CUKES_LOG_HANDLER=console go test ./tests-bdd/platform_test.go -v \
  --tags=cukes \
  features/obligations.feature:43
```

### ⚠️ Full Test Suite (Not Yet Supported in Containerized Mode)

Once the platform container uses Authorization v2 API:

```bash
# This will work after platform container is updated to v2 API
go test ./tests-bdd/platform_test.go -v \
  --tags=cukes \
  --godog.tags="@obligations"
```

Current limitation: The containerized platform may use v1 Authorization API which doesn't support obligations.

### Important Notes

1. **DEBUG Mode Limitation**: 
   - Only supports **ONE scenario at a time**
   - Use for debugging individual scenarios
   - Cannot run multiple scenarios concurrently

2. **Containerized Mode**:
   - Supports running all scenarios
   - Requires platform Docker image
   - Handles concurrent scenario execution properly

3. **Authorization v2 API**:
   - These tests use the **v2 Authorization API**
   - v1 API does not support obligations
   - v2 requires `FulfillableObligationFqns` in requests

## Test Coverage

All JIRA acceptance criteria are covered:

- ✅ **Obligation Definition & Values** - Create obligations with multiple values
- ✅ **Triggers on Attribute Values** - Link obligation values to actions on attribute values
- ✅ **Client ID Scoping** - Triggers scoped to specific PEP client IDs
- ✅ **Multi-Resource Decisions** - Multiple resources in single decision request
- ✅ **Entity Chains** - Obligations with entity chains (user -> app -> user flows)
- ✅ **ABAC Integration** - Obligations with attribute-based access control
- ✅ **Obligation FQN Validation** - Verify correct obligation value FQNs returned
- ✅ **Negative Cases** - No triggers, mismatched actions, etc.

## Key Discoveries

### Obligation FQN Format
The system uses abbreviated form `obl` instead of `obligation`:
```
https://example.com/obl/watermark/value/visible
```

### Fulfillable Obligations
The v2 API requires declaring which obligations the caller can fulfill:

```go
req := &authzV2.GetDecisionRequest{
    EntityIdentifier: ...,
    Action: ...,
    Resource: ...,
    FulfillableObligationFqns: []string{
        "https://example.com/obl/watermark/value/visible",
    },
}
```

Without this, the decision will be **DENY** even if the user is authorized.

### Decision Response
Obligations are returned in the response:

```go
resp.GetDecision().GetRequiredObligations() // []string
```

## Troubleshooting

### Test Fails with "nil pointer dereference"
- **Cause**: Multiple scenarios running concurrently in DEBUG mode
- **Solution**: Run single scenarios only, or use containerized mode

### Test Fails with "unauthenticated"
- **Cause**: Concurrent access to shared resources
- **Solution**: Use `@stateless` tag and run in containerized mode

### Decision returns DENY instead of PERMIT
- **Cause**: Missing fulfillable obligations in request
- **Solution**: Verify `FulfillableObligationFqns` includes all required obligations

### Obligations not in response
- **Cause**: Using v1 Authorization API instead of v2
- **Solution**: Ensure using `SDK.AuthorizationV2.GetDecision()`

## Future Enhancements

Potential additions to test coverage:
- Obligations with custom actions
- Obligations on registered resources
- Bulk decision requests with obligations
- Performance/load testing with obligations
- Obligation trigger deletion and updates
