package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	"github.com/opentdf/platform/service/pkg/subjectmappingbuiltin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestKeycloakUserAttributeSubjectMapping verifies that when using the Keycloak ERS,
// subject mapping selectors must match the Keycloak user object structure, NOT raw JWT
// claim names. Custom Keycloak user attributes are nested under `.attributes.<name>[]`,
// so a selector like `.department` will never match even if the JWT contains
// `"department": "Finance"`. The correct selector is `.attributes.department[]`.
//
// This test exists to document and verify actual Keycloak ERS behavior, and to serve
// as a reference for community members debugging subject mapping failures.
// See: https://github.com/orgs/opentdf/discussions/3115
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

	entityStruct, err := structpb.NewStruct(genericMap)
	require.NoError(t, err)

	entityRepresentation := &entityresolution.EntityRepresentation{
		OriginalId:      "jen",
		AdditionalProps: []*structpb.Struct{entityStruct},
	}

	// Log all flattened keys so the structure is visible in test output
	flattenedEntity, err := flattening.Flatten(genericMap)
	require.NoError(t, err)
	t.Log("Flattened Keycloak user keys:")
	for _, item := range flattenedEntity.Items {
		t.Logf("  key=%q value=%v", item.Key, item.Value)
	}

	const attrFQN = "https://example.com/attr/department/value/finance"

	t.Run("correct selector matches Keycloak user attribute", func(t *testing.T) {
		entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
			buildAttributeSubjectMapping(attrFQN, ".attributes.department[]", "Finance"),
			entityRepresentation,
		)
		require.NoError(t, err)
		assert.Equal(t, []string{attrFQN}, entitlements,
			"selector '.attributes.department[]' should match Keycloak user attribute")
	})

	t.Run("JWT claim name selector does not match Keycloak user object", func(t *testing.T) {
		entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
			buildAttributeSubjectMapping(attrFQN, ".department", "Finance"),
			entityRepresentation,
		)
		require.NoError(t, err)
		assert.Empty(t, entitlements,
			"selector '.department' should NOT match: Keycloak ERS resolves user objects, not JWT claims")
	})
}

func buildAttributeSubjectMapping(attrFQN, selector, value string) map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue { //nolint:unparam // attrFQN is parameterized so callers can specify any attribute FQN
	return map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		attrFQN: {
			Value: &policy.Value{
				SubjectMappings: []*policy.SubjectMapping{
					{
						SubjectConditionSet: &policy.SubjectConditionSet{
							SubjectSets: []*policy.SubjectSet{
								{
									ConditionGroups: []*policy.ConditionGroup{
										{
											BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
											Conditions: []*policy.Condition{
												{
													SubjectExternalSelectorValue: selector,
													Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
													SubjectExternalValues:        []string{value},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
