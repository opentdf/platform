package access

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	ers "github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/actions"
	"google.golang.org/protobuf/types/known/structpb"
)

// Constants for test namespaces
const (
	testBaseNamespace      = "test.example.com"
	testSecondaryNamespace = "secondary.example.org"
)

// Helper function to create attribute definition FQNs
func createAttrFQN(namespace, name string) string {
	attr := &identifier.FullyQualifiedAttribute{
		Namespace: namespace,
		Name:      name,
	}
	return attr.FQN()
}

// Helper function to create attribute value FQNs
func createAttrValueFQN(namespace, name, value string) string {
	attr := &identifier.FullyQualifiedAttribute{
		Namespace: namespace,
		Name:      name,
		Value:     value,
	}
	return attr.FQN()
}

// Attribute FQNs using identifier package
var (
	// Base attribute FQNs
	testClassificationFQN = createAttrFQN(testBaseNamespace, "classification")
	testDepartmentFQN     = createAttrFQN(testBaseNamespace, "department")
	testCountryFQN        = createAttrFQN(testBaseNamespace, "country")

	// Additional attributes from secondary namespace
	testProjectFQN  = createAttrFQN(testSecondaryNamespace, "project")
	testPlatformFQN = createAttrFQN(testSecondaryNamespace, "platform")

	// Classification values
	testClassTopSecretFQN    = createAttrValueFQN(testBaseNamespace, "classification", "topsecret")
	testClassSecretFQN       = createAttrValueFQN(testBaseNamespace, "classification", "secret")
	testClassConfidentialFQN = createAttrValueFQN(testBaseNamespace, "classification", "confidential")
	testClassPublicFQN       = createAttrValueFQN(testBaseNamespace, "classification", "public")

	// Department values
	testDeptRnDFQN         = createAttrValueFQN(testBaseNamespace, "department", "rnd")
	testDeptEngineeringFQN = createAttrValueFQN(testBaseNamespace, "department", "engineering")
	testDeptSalesFQN       = createAttrValueFQN(testBaseNamespace, "department", "sales")
	testDeptFinanceFQN     = createAttrValueFQN(testBaseNamespace, "department", "finance")

	// Country values
	testCountryUSAFQN = createAttrValueFQN(testBaseNamespace, "country", "usa")
	testCountryUKFQN  = createAttrValueFQN(testBaseNamespace, "country", "uk")

	// Project values in secondary namespace
	testProjectAlphaFQN = createAttrValueFQN(testSecondaryNamespace, "project", "alpha")
	testProjectBetaFQN  = createAttrValueFQN(testSecondaryNamespace, "project", "beta")
	testProjectGammaFQN = createAttrValueFQN(testSecondaryNamespace, "project", "gamma")

	// Platform values in secondary namespace
	testPlatformCloudFQN  = createAttrValueFQN(testSecondaryNamespace, "platform", "cloud")
	testPlatformOnPremFQN = createAttrValueFQN(testSecondaryNamespace, "platform", "onprem")
	testPlatformHybridFQN = createAttrValueFQN(testSecondaryNamespace, "platform", "hybrid")
)

// Standard action definitions used across tests
var (
	testActionRead   = &policy.Action{Name: actions.ActionNameRead}
	testActionCreate = &policy.Action{Name: actions.ActionNameCreate}
	testActionUpdate = &policy.Action{Name: actions.ActionNameUpdate}
	testActionDelete = &policy.Action{Name: actions.ActionNameDelete}
)

// Helper functions for all tests

// createResource creates a resource with attribute values
func createResource(ephemeralID string, attributeValueFQNs ...string) *authz.Resource {
	return &authz.Resource{
		EphemeralId: ephemeralID,
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{
				Fqns: attributeValueFQNs,
			},
		},
	}
}

// createResources creates multiple resources, one for each attribute value FQN
func createResources(attributeValueFQNs ...string) []*authz.Resource {
	resources := make([]*authz.Resource, len(attributeValueFQNs))
	for i, fqn := range attributeValueFQNs {
		// Use the FQN itself as the resource ID instead of a generic "ephemeral-id-X"
		resources[i] = createResource(fqn, fqn)
	}
	return resources
}

// actionNames extracts action names from a slice of actions
func actionNames(actions []*policy.Action) []string {
	names := make([]string, len(actions))
	for i, action := range actions {
		names[i] = action.GetName()
	}
	return names
}

// findEntityEntitlements finds entity entitlements by ID
func findEntityEntitlements(entitlements []*authz.EntityEntitlements, entityID string) *authz.EntityEntitlements {
	for _, e := range entitlements {
		if e != nil && e.EphemeralId == entityID {
			return e
		}
	}
	return nil
}

// createSimpleSubjectConditionSet creates a simple subject condition set with a single condition
// that checks if a property contains any of the specified values
func createSimpleSubjectConditionSet(selector string, values []string) *policy.SubjectConditionSet {
	// Create a single condition that uses the IN operator
	condition := &policy.Condition{
		SubjectExternalSelectorValue: selector,
		SubjectExternalValues:        values,
		Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
	}

	// Add the condition to a condition group with AND operator
	conditionGroup := &policy.ConditionGroup{
		BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
		Conditions:      []*policy.Condition{condition},
	}

	// Add the condition group to a subject set
	subjectSet := &policy.SubjectSet{
		ConditionGroups: []*policy.ConditionGroup{conditionGroup},
	}

	// Return the complete subject condition set
	return &policy.SubjectConditionSet{
		SubjectSets: []*policy.SubjectSet{subjectSet},
	}
}

// createSimpleSubjectMapping creates a complete subject mapping with a simple condition
func createSimpleSubjectMapping(attrValueFQN string, attrValue string, actions []*policy.Action, selector string, values []string) *policy.SubjectMapping {
	return &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   attrValueFQN,
			Value: attrValue,
		},
		SubjectConditionSet: createSimpleSubjectConditionSet(selector, values),
		Actions:             actions,
	}
}

// Helper function to test decision results
// findResourceDecision finds a decision result for a specific resource ID
func findResourceDecision(decision *Decision, resourceID string) *ResourceDecision {
	if decision == nil || len(decision.Results) == 0 {
		return nil
	}

	// Search for the exact resource ID in the results
	for _, result := range decision.Results {
		if result.ResourceID == resourceID {
			return &result
		}
	}
	return nil
}

// assertDecisionResult is a helper function to assert that a decision result for a given FQN matches the expected pass/fail state
func (s *PDPTestSuite) assertDecisionResult(decision *Decision, fqn string, shouldPass bool) {
	resourceDecision := findResourceDecision(decision, fqn)
	s.Require().NotNil(resourceDecision, fmt.Sprintf("No result found for FQN %s", fqn))
	s.Equal(shouldPass, resourceDecision.Passed, "Unexpected result for FQN %s. Expected (%t), got (%t)", fqn, shouldPass, resourceDecision.Passed)
}

// assertAllDecisionResults tests all FQNs in a map of FQN to expected pass/fail state
func (s *PDPTestSuite) assertAllDecisionResults(decision *Decision, expectedResults map[string]bool) {
	for fqn, shouldPass := range expectedResults {
		s.assertDecisionResult(decision, fqn, shouldPass)
	}
	// Verify we didn't miss any results
	s.Len(decision.Results, len(expectedResults), "Number of results doesn't match expected count")
}

// createEntityWithProps creates an entity representation with the specified properties
func (s *PDPTestSuite) createEntityWithProps(entityID string, props map[string]interface{}) *ers.EntityRepresentation {
	propsStruct := &structpb.Struct{
		Fields: make(map[string]*structpb.Value),
	}

	for k, v := range props {
		value, err := structpb.NewValue(v)
		if err != nil {
			panic(fmt.Sprintf("Failed to convert value %v to structpb.Value: %v", v, err))
		}
		propsStruct.Fields[k] = value
	}

	return &ers.EntityRepresentation{
		OriginalId: entityID,
		AdditionalProps: []*structpb.Struct{
			{
				Fields: map[string]*structpb.Value{
					"properties": structpb.NewStructValue(propsStruct),
				},
			},
		},
	}
}

// PDPTestSuite contains all the tests for the PolicyDecisionPoint
type PDPTestSuite struct {
	suite.Suite
	ctx      context.Context
	logger   *logger.Logger
	fixtures struct {
		// Test attributes
		classificationAttr *policy.Attribute
		departmentAttr     *policy.Attribute
		countryAttr        *policy.Attribute
		projectAttr        *policy.Attribute
		platformAttr       *policy.Attribute

		// Test subject mappings
		secretMapping        *policy.SubjectMapping
		confidentialMapping  *policy.SubjectMapping
		publicMapping        *policy.SubjectMapping
		engineeringMapping   *policy.SubjectMapping
		financeMapping       *policy.SubjectMapping
		rndMapping           *policy.SubjectMapping
		usaMapping           *policy.SubjectMapping
		projectAlphaMapping  *policy.SubjectMapping
		platformCloudMapping *policy.SubjectMapping

		// Test entity representations
		adminEntity     *ers.EntityRepresentation
		developerEntity *ers.EntityRepresentation
		analystEntity   *ers.EntityRepresentation
	}
}

// SetupTest initializes the test suite
func (s *PDPTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.logger = logger.CreateTestLogger()

	// Initialize attributes
	s.fixtures.classificationAttr = &policy.Attribute{
		Fqn:  testClassificationFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			{
				Fqn:   testClassTopSecretFQN,
				Value: "topsecret",
			},
			{
				Fqn:   testClassSecretFQN,
				Value: "secret",
			},
			{
				Fqn:   testClassConfidentialFQN,
				Value: "confidential",
			},
			{
				Fqn:   testClassPublicFQN,
				Value: "public",
			},
		},
	}
	s.fixtures.departmentAttr = &policy.Attribute{
		Fqn:  testDepartmentFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{
				Fqn:   testDeptRnDFQN,
				Value: "rnd",
			},
			{
				Fqn:   testDeptEngineeringFQN,
				Value: "engineering",
			},
			{
				Fqn:   testDeptSalesFQN,
				Value: "sales",
			},
			{
				Fqn:   testDeptFinanceFQN,
				Value: "finance",
			},
		},
	}
	s.fixtures.countryAttr = &policy.Attribute{
		Fqn:  testCountryFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Fqn:   testCountryUSAFQN,
				Value: "usa",
			},
			{
				Fqn:   testCountryUKFQN,
				Value: "uk",
			},
		},
	}
	s.fixtures.projectAttr = &policy.Attribute{
		Fqn:  testProjectFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{
				Fqn:   testProjectAlphaFQN,
				Value: "alpha",
			},
			{
				Fqn:   testProjectBetaFQN,
				Value: "beta",
			},
			{
				Fqn:   testProjectGammaFQN,
				Value: "gamma",
			},
		},
	}
	s.fixtures.platformAttr = &policy.Attribute{
		Fqn:  testPlatformFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{
				Fqn:   testPlatformCloudFQN,
				Value: "cloud",
			},
			{
				Fqn:   testPlatformOnPremFQN,
				Value: "onprem",
			},
			{
				Fqn:   testPlatformHybridFQN,
				Value: "hybrid",
			},
		},
	}

	// Initialize subject mappings
	s.fixtures.secretMapping = createSimpleSubjectMapping(
		testClassSecretFQN,
		"secret",
		[]*policy.Action{testActionRead, testActionUpdate},
		".properties.clearance",
		[]string{"secret"},
	)

	s.fixtures.confidentialMapping = createSimpleSubjectMapping(
		testClassConfidentialFQN,
		"confidential",
		[]*policy.Action{testActionRead},
		".properties.clearance",
		[]string{"confidential"},
	)

	s.fixtures.publicMapping = createSimpleSubjectMapping(
		testClassPublicFQN,
		"public",
		[]*policy.Action{testActionRead},
		".properties.clearance",
		[]string{"public"},
	)

	s.fixtures.engineeringMapping = createSimpleSubjectMapping(
		testDeptEngineeringFQN,
		"engineering",
		[]*policy.Action{testActionRead, testActionCreate},
		".properties.department",
		[]string{"engineering"},
	)

	s.fixtures.financeMapping = createSimpleSubjectMapping(
		testDeptFinanceFQN,
		"finance",
		[]*policy.Action{testActionRead, testActionUpdate},
		".properties.department",
		[]string{"finance"},
	)

	s.fixtures.rndMapping = createSimpleSubjectMapping(
		testDeptRnDFQN,
		"rnd",
		[]*policy.Action{testActionRead, testActionUpdate},
		".properties.department",
		[]string{"rnd"},
	)

	s.fixtures.usaMapping = createSimpleSubjectMapping(
		testCountryUSAFQN,
		"usa",
		[]*policy.Action{testActionRead},
		".properties.country[]",
		[]string{"us"},
	)

	s.fixtures.projectAlphaMapping = createSimpleSubjectMapping(
		testProjectAlphaFQN,
		"alpha",
		[]*policy.Action{testActionRead, testActionCreate},
		".properties.project",
		[]string{"alpha"},
	)

	s.fixtures.platformCloudMapping = createSimpleSubjectMapping(
		testPlatformCloudFQN,
		"cloud",
		[]*policy.Action{testActionRead, testActionDelete},
		".properties.platform",
		[]string{"cloud"},
	)

	// Initialize standard test entities
	s.fixtures.adminEntity = s.createEntityWithProps("admin-entity", map[string]interface{}{
		"clearance":  "secret",
		"department": "engineering",
		"country":    []any{"us"},
	})
	s.fixtures.developerEntity = s.createEntityWithProps("developer-entity", map[string]interface{}{
		"clearance":  "confidential",
		"department": "engineering",
		"country":    []any{"us"},
	})
	s.fixtures.analystEntity = s.createEntityWithProps("analyst-entity", map[string]interface{}{
		"clearance":  "confidential",
		"department": "finance",
		"country":    []any{"uk"},
	})
}

// TestPDPSuite runs the test suite
func TestPDPSuite(t *testing.T) {
	suite.Run(t, new(PDPTestSuite))
}

// TestNewPolicyDecisionPoint tests the creation of a new PDP
func (s *PDPTestSuite) TestNewPolicyDecisionPoint() {
	f := s.fixtures

	tests := []struct {
		name            string
		attributes      []*policy.Attribute
		subjectMappings []*policy.SubjectMapping
		expectError     bool
	}{
		{
			name:            "valid initialization",
			attributes:      []*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr},
			subjectMappings: []*policy.SubjectMapping{f.secretMapping, f.confidentialMapping, f.rndMapping},
			expectError:     false,
		},
		{
			name:            "nil attributes and subject mappings",
			attributes:      nil,
			subjectMappings: nil,
			expectError:     true,
		},
		{
			name:            "nil attributes but non-nil subject mappings",
			attributes:      nil,
			subjectMappings: []*policy.SubjectMapping{f.secretMapping},
			expectError:     true,
		},
		{
			name:            "non-nil attributes but nil subject mappings",
			attributes:      []*policy.Attribute{f.classificationAttr},
			subjectMappings: nil,
			expectError:     true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			pdp, err := NewPolicyDecisionPoint(s.ctx, s.logger, tc.attributes, tc.subjectMappings)

			if tc.expectError {
				s.Error(err)
				s.Nil(pdp)
			} else {
				s.NoError(err)
				s.NotNil(pdp)
			}
		})
	}
}

// Test_GetDecision tests the GetDecision method with some generalized scenarios
func (s *PDPTestSuite) Test_GetDecision() {
	f := s.fixtures

	// Create a PDP with relevant attributes and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.ctx,
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr},
		[]*policy.SubjectMapping{f.secretMapping, f.confidentialMapping, f.engineeringMapping, f.financeMapping},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Access granted when entity has appropriate entitlements", func() {
		// Entity with appropriate entitlements
		entity := s.createEntityWithProps("test-user-1", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
		})

		// Resource to evaluate (Secret classification)
		resources := createResources(testClassSecretFQN)

		// Get decision
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)
		s.Len(decision.Results, 1)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN: true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		s.Empty(decision.Results[0].DataRuleResults[0].EntitlementFailures)
	})

	s.Run("Access denied when entity lacks entitlements", func() {
		// Entity with insufficient entitlements
		entity := s.createEntityWithProps("test-user-2", map[string]interface{}{
			"clearance":  "confidential", // Not high enough for update on secret
			"department": "finance",      // Not engineering
		})

		// Resource to evaluate (Secret classification)
		resources := createResources(testClassSecretFQN)

		// Get decision for update action
		decision, err := pdp.GetDecision(s.ctx, entity, testActionUpdate, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 1)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN: false,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		s.NotEmpty(decision.Results[0].DataRuleResults[0].EntitlementFailures)
	})

	s.Run("Access denied for disallowed action", func() {
		// Entity with appropriate entitlements
		entity := s.createEntityWithProps("test-user-3", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
		})

		// Resource to evaluate (Engineering department)
		resources := createResources(testDeptEngineeringFQN)

		// Get decision for update action (not allowed on engineering)
		decision, err := pdp.GetDecision(s.ctx, entity, testActionUpdate, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 1)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testDeptEngineeringFQN: false,
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Multiple resources - partial access", func() {
		// Entity with mixed entitlements
		entity := s.createEntityWithProps("test-user-4", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
		})

		// Resources to evaluate (Secret classification and Finance department)
		resources := createResources(testClassSecretFQN, testDeptFinanceFQN)

		// Get decision
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // False because one resource is denied
		s.Len(decision.Results, 2)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN: true,
			testDeptFinanceFQN: false,
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Invalid resource FQN", func() {
		// Create test entity
		entity := s.createEntityWithProps("test-user-5", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
		})

		// Resource with invalid FQN
		resources := createResources(testBaseNamespace + "/attr/nonexistent/value/test")

		// Get decision
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, resources)

		// Assertions
		s.Require().Error(err)
		s.Nil(decision)
		s.Equal(ErrInvalidResource, err)
	})
}

// Test_GetDecision_AcrossNamespaces tests cross-namespace decisions with various scenarios
func (s *PDPTestSuite) Test_GetDecision_AcrossNamespaces() {
	f := s.fixtures

	// Create mappings for additional secondary namespace values
	betaMapping := createSimpleSubjectMapping(
		testProjectBetaFQN,
		"beta",
		[]*policy.Action{testActionRead, testActionUpdate},
		".properties.project",
		[]string{"beta"},
	)

	gammaMapping := createSimpleSubjectMapping(
		testProjectGammaFQN,
		"gamma",
		[]*policy.Action{testActionRead, testActionCreate, testActionDelete},
		".properties.project",
		[]string{"gamma"},
	)

	onPremMapping := createSimpleSubjectMapping(
		testPlatformOnPremFQN,
		"onprem",
		[]*policy.Action{testActionRead, testActionUpdate},
		".properties.platform",
		[]string{"onprem"},
	)

	hybridMapping := createSimpleSubjectMapping(
		testPlatformHybridFQN,
		"hybrid",
		[]*policy.Action{testActionRead, testActionCreate, testActionUpdate, testActionDelete},
		".properties.platform",
		[]string{"hybrid"},
	)

	// Create a PDP with attributes and mappings from all namespaces
	pdp, err := NewPolicyDecisionPoint(
		s.ctx,
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr, f.projectAttr, f.platformAttr},
		[]*policy.SubjectMapping{
			f.secretMapping, f.confidentialMapping, f.engineeringMapping, f.financeMapping,
			f.projectAlphaMapping, betaMapping, gammaMapping,
			f.platformCloudMapping, onPremMapping, hybridMapping,
			f.usaMapping,
		},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	// Basic cross-namespace scenarios
	s.Run("Cross-namespace access control - full access", func() {
		// Entity with entitlements for both namespaces
		entity := s.createEntityWithProps("cross-ns-user-1", map[string]interface{}{
			"clearance": "secret",
			"project":   "alpha",
			"platform":  "cloud",
		})

		// Resources from two different namespaces
		resources := createResources(testClassSecretFQN, testProjectAlphaFQN)

		// Request for a common action allowed by both mappings
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)
		s.Len(decision.Results, 2)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN:  true,
			testProjectAlphaFQN: true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Cross-namespace access control - partial access", func() {
		// Entity with partial entitlements
		entity := s.createEntityWithProps("cross-ns-user-2", map[string]interface{}{
			"clearance": "secret",
			"project":   "beta", // Not alpha
			"platform":  "cloud",
		})

		// Resources from two different namespaces
		resources := createResources(testClassSecretFQN, testProjectAlphaFQN)

		// Request for read action
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 2)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN:  true,  // Secret is accessible
			testProjectAlphaFQN: false, // Project Alpha is not accessible
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Action permitted by one namespace mapping but not the other", func() {
		// Entity with entitlements for both namespaces
		entity := s.createEntityWithProps("cross-ns-user-3", map[string]interface{}{
			"clearance": "secret",
			"project":   "alpha",
			"platform":  "cloud",
		})

		// Resources from two different namespaces
		resources := createResources(testClassSecretFQN, testProjectAlphaFQN)

		// Create action is permitted for project alpha but not for secret
		decision, err := pdp.GetDecision(s.ctx, entity, testActionCreate, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 2)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN:  false, // Secret doesn't allow create
			testProjectAlphaFQN: true,  // Project Alpha allows create
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	// More complex cross-namespace scenarios
	s.Run("Multiple resources from multiple namespaces", func() {
		// Entity with full entitlements
		entity := s.createEntityWithProps("cross-ns-user-4", map[string]interface{}{
			"clearance": "secret",
			"project":   "alpha",
			"platform":  "cloud",
		})

		// Multiple resources from different namespaces
		resources := createResources(
			testClassSecretFQN,
			testClassConfidentialFQN,
			testProjectAlphaFQN,
			testPlatformCloudFQN,
		)

		// Request for delete action - allowed only by platform cloud mapping
		decision, err := pdp.GetDecision(s.ctx, entity, testActionDelete, resources)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 4)

		// Use FQN-based assertions
		expectedResults := map[string]bool{
			testClassSecretFQN:       false, // Secret doesn't allow delete
			testClassConfidentialFQN: false, // Confidential doesn't allow delete
			testProjectAlphaFQN:      false, // Project Alpha doesn't allow delete
			testPlatformCloudFQN:     true,  // Platform Cloud allows delete
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Mixed namespace resources in a single resource", func() {
		// Entity with full entitlements
		entity := s.createEntityWithProps("cross-ns-user-5", map[string]interface{}{
			"clearance": "secret",
			"project":   "alpha",
			"platform":  "cloud",
		})

		// A single resource with FQNs from different namespaces
		// Set a specific ID for this combined resource
		combinedResource := &authz.Resource{
			EphemeralId: "combined-resource",
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{testClassSecretFQN, testProjectAlphaFQN},
				},
			},
		}

		// Request for read action
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, []*authz.Resource{combinedResource})

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// The implementation treats this as a single resource with multiple rules
		s.Len(decision.Results, 1)
		s.Equal("combined-resource", decision.Results[0].ResourceID)

		// Instead of checking by FQN, confirm all data rule results pass
		for _, dataRule := range decision.Results[0].DataRuleResults {
			s.True(dataRule.Passed, "All data rules should pass")
			s.Empty(dataRule.EntitlementFailures, "There should be no entitlement failures")
		}
	})

	// Additional complex scenarios from Test_GetDecision_ComplexNamespaceInteractions
	s.Run("Entity with entitlements across three namespaces", func() {
		// Entity with entitlements from all three namespaces
		entity := s.createEntityWithProps("tri-namespace-entity", map[string]interface{}{
			"clearance":  "secret",      // from base namespace
			"project":    "alpha",       // from secondary namespace
			"platform":   "hybrid",      // from secondary namespace
			"country":    []any{"us"},   // ALL_OF rule
			"department": "engineering", // ANY_OF rule
		})

		// Resources from all namespaces
		resources := createResources(
			testClassSecretFQN,     // base namespace
			testDeptEngineeringFQN, // base namespace
			testCountryUSAFQN,      // base namespace - ALL_OF
			testProjectAlphaFQN,    // secondary namespace
			testPlatformHybridFQN,  // secondary namespace
		)

		// Test read access - should pass for all namespaces
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, resources)

		// Assertions
		s.Require().NoError(err)
		s.True(decision.Access)
		s.Len(decision.Results, 5)

		decisionResults := map[string]bool{
			testClassSecretFQN:     true, // Secret
			testDeptEngineeringFQN: true, // Engineering
			testCountryUSAFQN:      true, // USA
			testProjectAlphaFQN:    true, // Project Alpha
			testPlatformHybridFQN:  true, // Platform Hybrid
		}
		s.assertAllDecisionResults(decision, decisionResults)

		// Test delete access - should only pass for hybrid platform
		decision, err = pdp.GetDecision(s.ctx, entity, testActionDelete, resources)

		// Overall access should be denied
		s.Require().NoError(err)
		s.False(decision.Access)
		s.Len(decision.Results, 5)

		// Only hybrid platform allows delete
		decisionResults = map[string]bool{
			testClassSecretFQN:     false, // Secret - no delete
			testDeptEngineeringFQN: false, // Engineering - no delete
			testCountryUSAFQN:      false, // USA - no delete
			testProjectAlphaFQN:    false, // Project Alpha - no delete
			testPlatformHybridFQN:  true,  // Platform Hybrid - allows delete
		}
		s.assertAllDecisionResults(decision, decisionResults)
	})

	s.Run("Resources from all namespaces in a single resource", func() {
		// Entity with entitlements from all namespaces
		entity := s.createEntityWithProps("multi-ns-entity", map[string]interface{}{
			"clearance": "secret",
			"project":   "beta",
			"platform":  "onprem",
			"country":   []any{"us"},
		})

		// A single resource with attribute values from different namespaces
		combinedResource := &authz.Resource{
			EphemeralId: "combined-multi-ns-resource", // Explicitly set a resource ID
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{
						testClassSecretFQN,    // base namespace
						testCountryUSAFQN,     // base namespace
						testProjectBetaFQN,    // secondary namespace
						testPlatformOnPremFQN, // secondary namespace
					},
				},
			},
		}

		// Test read access - should pass for this combined resource
		decision, err := pdp.GetDecision(s.ctx, entity, testActionRead, []*authz.Resource{combinedResource})

		// Assertions
		s.Require().NoError(err)
		s.True(decision.Access)

		// The implementation treats this as a single resource with multiple rules
		s.Len(decision.Results, 1)
		s.Equal("combined-multi-ns-resource", decision.Results[0].ResourceID)

		// Instead of checking FQN by FQN, verify all data rules pass
		s.Len(decision.Results[0].DataRuleResults, 4) // Should have 4 data rules (one for each FQN)
		for _, dataRule := range decision.Results[0].DataRuleResults {
			s.True(dataRule.Passed, "All data rules should pass for read action")
			s.Empty(dataRule.EntitlementFailures, "There should be no entitlement failures for read action")
		}

		// Test update access - should pass for all except country
		decision, err = pdp.GetDecision(s.ctx, entity, testActionUpdate, []*authz.Resource{combinedResource})

		// Overall access should be denied due to country not supporting update
		s.Require().NoError(err)
		s.False(decision.Access)
		s.Len(decision.Results, 1)
		s.Equal("combined-multi-ns-resource", decision.Results[0].ResourceID)

		// There should be 4 data rules, with some failing
		s.Len(decision.Results[0].DataRuleResults, 4)

		// Count passes and failures
		passCount := 0
		failCount := 0
		for _, dataRule := range decision.Results[0].DataRuleResults {
			if dataRule.Passed {
				passCount++
				s.Empty(dataRule.EntitlementFailures)
			} else {
				failCount++
				s.NotEmpty(dataRule.EntitlementFailures)
			}
		}

		// Expect 3 passes (Secret, Project Beta, Platform OnPrem) and 1 failure (Country USA)
		s.Equal(3, passCount, "Should have 3 passing data rules for update action")
		s.Equal(1, failCount, "Should have 1 failing data rule for update action")
	})
}

// TestGetEntitlements tests the functionality of retrieving entitlements for entities
func (s *PDPTestSuite) Test_GetEntitlements() {
	f := s.fixtures

	// Create a PDP with attributes and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.ctx,
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr},
		[]*policy.SubjectMapping{
			f.secretMapping, f.confidentialMapping, f.publicMapping,
			f.engineeringMapping, f.financeMapping, f.rndMapping,
			f.usaMapping,
		},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Entity with multiple entitlements", func() {
		// Entity with entitlements for secret clearance, engineering department, and USA country
		entity := s.createEntityWithProps("test-entity-1", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
			"country":    []any{"us"},
		})

		// Get entitlements for this entity
		entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entity}, nil, false)

		// Assertions
		s.Require().NoError(err)
		s.Require().NotNil(entitlements)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "test-entity-1")
		s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")

		// Verify entitlements for classification
		secretActions := entityEntitlement.ActionsPerAttributeValueFqn[testClassSecretFQN]
		s.Require().NotNil(secretActions, "Secret classification entitlements should exist")
		s.Contains(actionNames(secretActions.Actions), actions.ActionNameRead)
		s.Contains(actionNames(secretActions.Actions), actions.ActionNameUpdate)

		// Verify entitlements for department
		engineeringActions := entityEntitlement.ActionsPerAttributeValueFqn[testDeptEngineeringFQN]
		s.Require().NotNil(engineeringActions, "Engineering department entitlements should exist")
		s.Contains(actionNames(engineeringActions.Actions), actions.ActionNameRead)
		s.Contains(actionNames(engineeringActions.Actions), actions.ActionNameCreate)

		// Verify entitlements for country
		usaActions := entityEntitlement.ActionsPerAttributeValueFqn[testCountryUSAFQN]
		s.Require().NotNil(usaActions, "USA country entitlements should exist")
		s.Contains(actionNames(usaActions.Actions), actions.ActionNameRead)
	})

	s.Run("Entity with no matching entitlements", func() {
		// Entity with no entitlements based on properties
		entity := s.createEntityWithProps("test-entity-2", map[string]interface{}{
			"clearance":  "unknown",
			"department": "unknown",
			"country":    []any{"unknown"},
		})

		// Get entitlements for this entity
		entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entity}, nil, false)

		// Assertions
		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "test-entity-2")
		s.Require().NotNil(entityEntitlement, "Entity should be included in results even with no entitlements")
		s.Empty(entityEntitlement.ActionsPerAttributeValueFqn, "No attribute value FQNs should be mapped for this entity")
	})

	s.Run("Entity with partial entitlements", func() {
		// Entity with some entitlements
		entity := s.createEntityWithProps("test-entity-3", map[string]interface{}{
			"clearance":  "public",
			"department": "sales", // No mapping for sales
		})

		// Get entitlements for this entity
		entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entity}, nil, false)

		// Assertions
		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "test-entity-3")
		s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")

		// Verify public classification entitlements exist
		s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, testClassPublicFQN, "Public classification entitlements should exist")
		publicActions := entityEntitlement.ActionsPerAttributeValueFqn[testClassPublicFQN]
		s.Contains(actionNames(publicActions.Actions), actions.ActionNameRead)

		// Verify sales department entitlements do not exist
		s.NotContains(entityEntitlement.ActionsPerAttributeValueFqn, testDeptSalesFQN, "Sales department should not have entitlements")
	})

	s.Run("Multiple entities with various entitlements", func() {
		entityCases := []struct {
			name                 string
			entityRepresentation *ers.EntityRepresentation
			expectedEntitlements []string
		}{
			{
				name:                 "admin-entity",
				entityRepresentation: f.adminEntity,
				expectedEntitlements: []string{testClassSecretFQN, testDeptEngineeringFQN, testCountryUSAFQN},
			},
			{
				name:                 "developer-entity",
				entityRepresentation: f.developerEntity,
				expectedEntitlements: []string{testClassConfidentialFQN, testDeptEngineeringFQN, testCountryUSAFQN},
			},
			{
				name:                 "analyst-entity",
				entityRepresentation: f.analystEntity,
				expectedEntitlements: []string{testClassConfidentialFQN, testDeptFinanceFQN},
			},
		}

		for _, entityCase := range entityCases {
			s.Run(entityCase.name, func() {
				// Get entitlements for this entity
				entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entityCase.entityRepresentation}, nil, false)

				// Assertions
				s.Require().NoError(err)

				// Find the entity's entitlements
				entityEntitlement := findEntityEntitlements(entitlements, entityCase.name)
				s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")
				s.Require().Len(entityEntitlement.ActionsPerAttributeValueFqn, len(entityCase.expectedEntitlements), "Number of entitlements should match expected")

				// Verify expected entitlements exist
				for _, expectedFQN := range entityCase.expectedEntitlements {
					s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, expectedFQN)
				}
			})
		}
	})

	s.Run("With comprehensive hierarchy", func() {
		// Entity with secret clearance
		entity := s.createEntityWithProps("hierarchy-test-entity", map[string]interface{}{
			"clearance": "secret",
		})

		// Get entitlements with comprehensive hierarchy
		entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entity}, nil, true)

		// Assertions
		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "hierarchy-test-entity")
		s.Require().NotNil(entityEntitlement)

		// With comprehensive hierarchy, the entity should have access to secret and all lower classifications
		s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, testClassSecretFQN)

		// The function populateLowerValuesIfHierarchy assumes the values in the hierarchy are arranged
		// in order from highest to lowest. In our test fixture, that means:
		// topsecret > secret > confidential > public

		// Secret clearance should give access to confidential and public (the items lower in the list)
		s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, testClassConfidentialFQN)
		s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, testClassPublicFQN)

		// But not to higher classifications
		s.NotContains(entityEntitlement.ActionsPerAttributeValueFqn, testClassTopSecretFQN)

		// Verify the actions for the lower levels match those granted to the secret level
		secretActions := entityEntitlement.ActionsPerAttributeValueFqn[testClassSecretFQN]
		s.Require().NotNil(secretActions)

		confidentialActions := entityEntitlement.ActionsPerAttributeValueFqn[testClassConfidentialFQN]
		s.Require().NotNil(confidentialActions)

		publicActions := entityEntitlement.ActionsPerAttributeValueFqn[testClassPublicFQN]
		s.Require().NotNil(publicActions)

		s.Len(secretActions.Actions, len(f.secretMapping.GetActions()))

		// The actions should be the same for all levels
		s.ElementsMatch(
			actionNames(secretActions.Actions),
			actionNames(confidentialActions.Actions),
			"Secret and confidential should have the same actions")

		s.ElementsMatch(
			actionNames(secretActions.Actions),
			actionNames(publicActions.Actions),
			"Secret and public should have the same actions")
	})

	s.Run("With filtered subject mappings", func() {
		// Entity with multiple entitlements
		entity := s.createEntityWithProps("filtered-test-entity", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
			"country":    []any{"us"},
		})

		// Filter to only classification mappings
		filteredMappings := []*policy.SubjectMapping{f.secretMapping, f.confidentialMapping, f.publicMapping}

		// Get entitlements with filtered mappings
		entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entity}, filteredMappings, false)

		// Assertions
		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "filtered-test-entity")
		s.Require().NotNil(entityEntitlement)

		// Should only have classification entitlements
		s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, testClassSecretFQN)

		// Should not have department or country entitlements
		s.NotContains(entityEntitlement.ActionsPerAttributeValueFqn, testDeptEngineeringFQN)
		s.NotContains(entityEntitlement.ActionsPerAttributeValueFqn, testCountryUSAFQN)
	})
}

func (s *PDPTestSuite) Test_GetEntitlements_AdvancedHierarchy() {
	testAdvancedHierarchyNs := "advanced.hier"
	hierarchyAttrName := "hierarchy_attr"
	actionNameTransmit := "custom_transmit"
	customActionGather := "gather"

	hierarchyTestAttrName := createAttrFQN(testAdvancedHierarchyNs, hierarchyAttrName)

	topValueFQN := createAttrValueFQN(testAdvancedHierarchyNs, hierarchyAttrName, "top")
	upperMiddleValueFQN := createAttrValueFQN(testAdvancedHierarchyNs, hierarchyAttrName, "upper-middle")
	middleValueFQN := createAttrValueFQN(testAdvancedHierarchyNs, hierarchyAttrName, "middle")
	lowerMiddleValueFQN := createAttrValueFQN(testAdvancedHierarchyNs, hierarchyAttrName, "lower-middle")
	bottomValueFQN := createAttrValueFQN(testAdvancedHierarchyNs, hierarchyAttrName, "bottom")

	hierarchyAttribute := &policy.Attribute{
		Fqn:  hierarchyTestAttrName,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			{
				Fqn:   topValueFQN,
				Value: "top",
			},
			{
				Fqn:   upperMiddleValueFQN,
				Value: "upper-middle",
			},
			{
				Fqn:   middleValueFQN,
				Value: "middle",
			},
			{
				Fqn:   lowerMiddleValueFQN,
				Value: "lower-middle",
			},
			{
				Fqn:   bottomValueFQN,
				Value: "bottom",
			},
		},
	}

	topMapping := createSimpleSubjectMapping(
		topValueFQN,
		"top",
		[]*policy.Action{testActionRead},
		".properties.levels[]",
		[]string{"top"},
	)
	upperMiddleMapping := createSimpleSubjectMapping(
		upperMiddleValueFQN,
		"upper-middle",
		[]*policy.Action{testActionCreate},
		".properties.levels[]",
		[]string{"upper-middle"},
	)
	middleMapping := createSimpleSubjectMapping(
		middleValueFQN,
		"middle",
		[]*policy.Action{testActionUpdate, {Name: actionNameTransmit}},
		".properties.levels[]",
		[]string{"middle"},
	)
	lowerMiddleMapping := createSimpleSubjectMapping(
		lowerMiddleValueFQN,
		"lower-middle",
		[]*policy.Action{testActionDelete},
		".properties.levels[]",
		[]string{"lower-middle"},
	)
	bottomMapping := createSimpleSubjectMapping(
		bottomValueFQN,
		"bottom",
		[]*policy.Action{{Name: customActionGather}},
		".properties.levels[]",
		[]string{"bottom"},
	)

	// Create a PDP with the hierarchy attribute and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.ctx,
		s.logger,
		[]*policy.Attribute{hierarchyAttribute},
		[]*policy.SubjectMapping{
			topMapping,
			upperMiddleMapping,
			middleMapping,
			lowerMiddleMapping,
			bottomMapping,
		},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	// Create an entity with every level in the hierarchy
	entity := s.createEntityWithProps("hierarchy-test-entity", map[string]interface{}{
		"levels": []any{"top", "upper-middle", "middle", "lower-middle", "bottom"},
	})

	// Get entitlements for this entity
	withComprehensiveHierarchy := true
	entitlements, err := pdp.GetEntitlements(s.ctx, []*ers.EntityRepresentation{entity}, nil, withComprehensiveHierarchy)
	s.Require().NoError(err)
	s.Require().NotNil(entitlements)

	// Find the entity's entitlements
	entityEntitlement := findEntityEntitlements(entitlements, "hierarchy-test-entity")
	s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")
	s.Require().Len(entityEntitlement.ActionsPerAttributeValueFqn, 5, "Number of entitlements should match expected")
	s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, topValueFQN, "Top level should be present")
	s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, upperMiddleValueFQN, "Upper-middle level should be present")
	s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, middleValueFQN, "Middle level should be present")
	s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, lowerMiddleValueFQN, "Lower-middle level should be present")
	s.Contains(entityEntitlement.ActionsPerAttributeValueFqn, bottomValueFQN, "Bottom level should be present")

	// Verify actions for each level
	topActions := entityEntitlement.ActionsPerAttributeValueFqn[topValueFQN]
	s.Require().NotNil(topActions, "Top level actions should exist")
	s.Len(topActions.Actions, 1)
	s.Contains(actionNames(topActions.Actions), actions.ActionNameRead, "Top level should have read action")

	upperMiddleActions := entityEntitlement.ActionsPerAttributeValueFqn[upperMiddleValueFQN]
	s.Require().NotNil(upperMiddleActions, "Upper-middle level actions should exist")
	s.Len(upperMiddleActions.Actions, 2)
	upperMiddleActionNames := actionNames(upperMiddleActions.Actions)
	s.Contains(upperMiddleActionNames, actions.ActionNameCreate, "Upper-middle level should have create action")
	s.Contains(upperMiddleActionNames, actions.ActionNameRead, "Upper-middle level should have read action")

	middleActions := entityEntitlement.ActionsPerAttributeValueFqn[middleValueFQN]
	s.Require().NotNil(middleActions, "Middle level actions should exist")
	s.Len(middleActions.Actions, 4)
	middleActionNames := actionNames(middleActions.Actions)
	s.Contains(middleActionNames, actions.ActionNameUpdate, "Middle level should have update action")
	s.Contains(middleActionNames, actionNameTransmit, "Middle level should have transmit action")
	s.Contains(middleActionNames, actions.ActionNameCreate, "Middle level should have create action")
	s.Contains(middleActionNames, actions.ActionNameRead, "Middle level should have read action")

	lowerMiddleActions := entityEntitlement.ActionsPerAttributeValueFqn[lowerMiddleValueFQN]
	s.Require().NotNil(lowerMiddleActions, "Lower-middle level actions should exist")
	s.Len(lowerMiddleActions.Actions, 5)
	lowerMiddleActionNames := actionNames(lowerMiddleActions.Actions)
	s.Contains(lowerMiddleActionNames, actions.ActionNameDelete, "Lower-middle level should have delete action")
	s.Contains(lowerMiddleActionNames, actions.ActionNameUpdate, "Lower-middle level should have update action")
	s.Contains(lowerMiddleActionNames, actions.ActionNameCreate, "Lower-middle level should have create action")
	s.Contains(lowerMiddleActionNames, actionNameTransmit, "Lower-middle level should have read action")
	s.Contains(lowerMiddleActionNames, actions.ActionNameRead, "Lower-middle level should have read action")

	bottomActions := entityEntitlement.ActionsPerAttributeValueFqn[bottomValueFQN]
	s.Require().NotNil(bottomActions, "Bottom level actions should exist")
	s.Len(bottomActions.Actions, 6)
	s.Contains(actionNames(bottomActions.Actions), actions.ActionNameRead, "Bottom level should have read action")
	s.Contains(actionNames(bottomActions.Actions), actions.ActionNameUpdate, "Bottom level should have update action")
	s.Contains(actionNames(bottomActions.Actions), actions.ActionNameCreate, "Bottom level should have create action")
	s.Contains(actionNames(bottomActions.Actions), actions.ActionNameDelete, "Bottom level should have delete action")
	s.Contains(actionNames(bottomActions.Actions), actionNameTransmit, "Bottom level should have transmit action")
	s.Contains(actionNames(bottomActions.Actions), customActionGather, "Bottom level should have gather action")
}
