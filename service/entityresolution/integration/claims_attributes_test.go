package integration

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestClaimsERSSubjectMapping verifies that when the ERS is configured with
// mode: "claims", subject mapping selectors match JWT private claim names
// directly at the top level of the entity — e.g. ".department" matches a token
// containing "department": "Finance".
//
// The correct selector also depends on the multi-valued setting of the Keycloak
// User Attribute mapper:
//   - Multi-valued OFF → claim is emitted as a string → use ".department"
//   - Multi-valued ON  → claim is emitted as an array  → use ".department[]"
//
// Contrast with TestKeycloakUserAttributeSubjectMapping: in Keycloak ERS mode
// (the default), the entity is a Keycloak user object where custom attributes
// are nested under ".attributes.<name>[]", not at ".<name>".
//
// See: https://github.com/opentdf/platform/blob/main/docs/Configuring.md#L479
func TestClaimsERSSubjectMapping(t *testing.T) {
	const attrFQN = "https://example.com/attr/department/value/finance"

	// Simulate what the Claims ERS does: token.PrivateClaims() returns a flat
	// map of JWT claim name → value, which is converted to structpb.Struct and
	// used as the entity directly (no Keycloak user object lookup).

	t.Run("multi-valued OFF: claim is a string, selector is .department", func(t *testing.T) {
		// Keycloak User Attribute mapper with multi-valued OFF emits a plain string.
		entityStruct, err := structpb.NewStruct(map[string]interface{}{
			"department": "Finance",
			"sub":        "jen",
		})
		require.NoError(t, err)
		entity := &entityresolution.EntityRepresentation{
			OriginalId:      "jen",
			AdditionalProps: []*structpb.Struct{entityStruct},
		}

		t.Run("string selector matches", func(t *testing.T) {
			entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
				buildAttributeSubjectMapping(attrFQN, ".department", "Finance"),
				entity,
			)
			require.NoError(t, err)
			assert.Equal(t, []string{attrFQN}, entitlements,
				"selector '.department' should match a string-valued JWT claim")
		})

		t.Run("array selector does not match", func(t *testing.T) {
			entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
				buildAttributeSubjectMapping(attrFQN, ".department[]", "Finance"),
				entity,
			)
			require.NoError(t, err)
			assert.Empty(t, entitlements,
				"selector '.department[]' should NOT match when the claim is a string, not an array")
		})
	})

	t.Run("multi-valued ON: claim is an array, selector is .department[]", func(t *testing.T) {
		// Keycloak User Attribute mapper with multi-valued ON emits an array.
		entityStruct, err := structpb.NewStruct(map[string]interface{}{
			"department": []interface{}{"Finance"},
			"sub":        "jen",
		})
		require.NoError(t, err)
		entity := &entityresolution.EntityRepresentation{
			OriginalId:      "jen",
			AdditionalProps: []*structpb.Struct{entityStruct},
		}

		t.Run("array selector matches", func(t *testing.T) {
			entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
				buildAttributeSubjectMapping(attrFQN, ".department[]", "Finance"),
				entity,
			)
			require.NoError(t, err)
			assert.Equal(t, []string{attrFQN}, entitlements,
				"selector '.department[]' should match an array-valued JWT claim")
		})

		t.Run("string selector does not match", func(t *testing.T) {
			entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
				buildAttributeSubjectMapping(attrFQN, ".department", "Finance"),
				entity,
			)
			require.NoError(t, err)
			assert.Empty(t, entitlements,
				"selector '.department' should NOT match when the claim is an array, not a string")
		})
	})

	t.Run("Keycloak-style nested selector never matches claims-mode entity", func(t *testing.T) {
		entityStruct, err := structpb.NewStruct(map[string]interface{}{
			"department": "Finance",
			"sub":        "jen",
		})
		require.NoError(t, err)
		entity := &entityresolution.EntityRepresentation{
			OriginalId:      "jen",
			AdditionalProps: []*structpb.Struct{entityStruct},
		}

		entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
			buildAttributeSubjectMapping(attrFQN, ".attributes.department[]", "Finance"),
			entity,
		)
		require.NoError(t, err)
		assert.Empty(t, entitlements,
			"selector '.attributes.department[]' should NOT match: claims entities are flat JWT claims, not Keycloak user objects")
	})
}
