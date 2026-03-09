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
// Contrast with TestKeycloakUserAttributeSubjectMapping: in Keycloak ERS mode
// (the default), the entity is a Keycloak user object where custom attributes
// are nested under ".attributes.<name>[]", not at ".<name>".
//
// See: https://github.com/opentdf/platform/blob/main/docs/Configuring.md#L479
func TestClaimsERSSubjectMapping(t *testing.T) {
	// Simulate what the Claims ERS does: token.PrivateClaims() returns a flat
	// map of JWT claim name → value, which is converted to structpb.Struct and
	// used as the entity directly (no Keycloak user object lookup).
	jwtClaims := map[string]interface{}{
		"department": "Finance",
		"sub":        "jen",
	}
	entityStruct, err := structpb.NewStruct(jwtClaims)
	require.NoError(t, err)

	entityRepresentation := &entityresolution.EntityRepresentation{
		OriginalId:      "jen",
		AdditionalProps: []*structpb.Struct{entityStruct},
	}

	const attrFQN = "https://example.com/attr/department/value/finance"

	t.Run("JWT claim name selector matches claims-mode entity", func(t *testing.T) {
		entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
			buildAttributeSubjectMapping(attrFQN, ".department", "Finance"),
			entityRepresentation,
		)
		require.NoError(t, err)
		assert.Equal(t, []string{attrFQN}, entitlements,
			"selector '.department' should match when ERS is in mode: claims and the JWT contains department=Finance")
	})

	t.Run("Keycloak-style nested selector does not match claims-mode entity", func(t *testing.T) {
		entitlements, err := subjectmappingbuiltin.EvaluateSubjectMappings(
			buildAttributeSubjectMapping(attrFQN, ".attributes.department[]", "Finance"),
			entityRepresentation,
		)
		require.NoError(t, err)
		assert.Empty(t, entitlements,
			"selector '.attributes.department[]' should NOT match: claims entities are flat JWT claims, not Keycloak user objects")
	})
}
