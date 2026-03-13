package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/test/integration/entityresolution/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeycloakUserAttributeSubjectMapping verifies that when using the Keycloak ERS,
// custom user attributes are nested under ".attributes.<name>[]" in the flattened
// entity, NOT at the top level as ".<name>". This means subject mapping selectors
// must use ".attributes.department[]" rather than ".department".
//
// This test exists to document and verify actual Keycloak ERS behavior, and to serve
// as a reference for community members debugging subject mapping failures.
// See: https://github.com/orgs/opentdf/discussions/3115
//
// The actual selector evaluation logic is unit-tested in
// service/internal/subjectmappingbuiltin/claims_attributes_test.go.
func TestKeycloakUserAttributeSubjectMapping(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Keycloak integration tests in short mode")
	}

	defer func() {
		if r := recover(); r != nil {
			if panicStr := fmt.Sprintf("%v", r); strings.Contains(panicStr, "Docker") || strings.Contains(panicStr, "docker") {
				t.Skipf("Docker not available for Keycloak container tests: %v", r)
			} else {
				panic(r)
			}
		}
	}()

	ctx := context.Background()

	adapter := NewKeycloakTestAdapter()

	require.NoError(t, adapter.SetupTestData(ctx, &internal.ContractTestDataSet{}))
	defer adapter.TeardownTestData(ctx) //nolint:errcheck // teardown is best-effort; failure doesn't affect test outcome

	// Create a user with a 'department' Keycloak attribute — mirroring the scenario
	// in https://github.com/orgs/opentdf/discussions/3115
	dept := map[string][]string{"department": {"Finance"}}
	keycloakUser := gocloak.User{
		Username:      gocloak.StringP("jen"),
		Email:         gocloak.StringP("jen@email.com"),
		FirstName:     gocloak.StringP("Jen Z"),
		Enabled:       gocloak.BoolP(true),
		EmailVerified: gocloak.BoolP(true),
		Attributes:    &dept,
	}
	_, err := adapter.keycloakClient.CreateUser(ctx, adapter.adminToken.AccessToken, adapter.config.Realm, keycloakUser)
	require.NoError(t, err)

	// Retrieve the user exactly as the Keycloak ERS does via GetUsers
	exactMatch := true
	users, err := adapter.keycloakClient.GetUsers(ctx, adapter.adminToken.AccessToken, adapter.config.Realm, gocloak.GetUsersParams{
		Username: gocloak.StringP("jen"),
		Exact:    &exactMatch,
	})
	require.NoError(t, err)
	require.Len(t, users, 1)

	// Serialize the user exactly as typeToGenericJSONMap does in the Keycloak ERS
	userJSON, err := json.Marshal(users[0])
	require.NoError(t, err)
	t.Logf("Keycloak user object JSON: %s", userJSON)

	var genericMap map[string]interface{}
	err = json.Unmarshal(userJSON, &genericMap)
	require.NoError(t, err)

	// Flatten the entity and verify the key structure matches what the
	// subject mapping evaluator will see at runtime.
	flattenedEntity, err := flattening.Flatten(genericMap)
	require.NoError(t, err)

	flatKeys := make(map[string]interface{})
	for _, item := range flattenedEntity.Items {
		t.Logf("  key=%q value=%v", item.Key, item.Value)
		flatKeys[item.Key] = item.Value
	}

	t.Run("correct selector key exists in flattened entity", func(t *testing.T) {
		// The Keycloak ERS nests custom attributes under .attributes.<name>[]
		assert.Contains(t, flatKeys, ".attributes.department[]",
			"Keycloak user attribute should be flattened as '.attributes.department[]'")
	})

	t.Run("JWT claim name key does not exist in flattened entity", func(t *testing.T) {
		// A bare .department key should NOT appear — this is why selectors
		// like ".department" fail against Keycloak ERS entities.
		assert.NotContains(t, flatKeys, ".department",
			"bare '.department' should NOT be a key in a Keycloak user entity")
	})
}
