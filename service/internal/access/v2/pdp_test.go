package access

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/opentdf/platform/lib/identifier"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
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

// PDPTestSuite contains all the tests for the PolicyDecisionPoint
type PDPTestSuite struct {
	suite.Suite
	logger   *logger.Logger
	fixtures struct {
		// Test attributes
		classificationAttr *policy.Attribute
		departmentAttr     *policy.Attribute
		countryAttr        *policy.Attribute
		projectAttr        *policy.Attribute
		platformAttr       *policy.Attribute

		// Test subject mappings
		topSecretMapping     *policy.SubjectMapping
		secretMapping        *policy.SubjectMapping
		confidentialMapping  *policy.SubjectMapping
		publicMapping        *policy.SubjectMapping
		engineeringMapping   *policy.SubjectMapping
		financeMapping       *policy.SubjectMapping
		rndMapping           *policy.SubjectMapping
		usaMapping           *policy.SubjectMapping
		ukMapping            *policy.SubjectMapping
		projectAlphaMapping  *policy.SubjectMapping
		platformCloudMapping *policy.SubjectMapping

		// Test entity representations
		adminEntity     *entityresolutionV2.EntityRepresentation
		developerEntity *entityresolutionV2.EntityRepresentation
		analystEntity   *entityresolutionV2.EntityRepresentation

		// Test registered resources
		simpleRegisteredResource *policy.RegisteredResource
	}
}

// SetupTest initializes the test suite
func (s *PDPTestSuite) SetupTest() {
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
	s.fixtures.topSecretMapping = createSimpleSubjectMapping(
		testClassSecretFQN,
		"topsecret",
		[]*policy.Action{testActionRead},
		".properties.clearance",
		[]string{"ts"},
	)

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

	s.fixtures.ukMapping = createSimpleSubjectMapping(
		testCountryUKFQN,
		"uk",
		[]*policy.Action{testActionRead},
		".properties.country[]",
		[]string{"uk"},
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

	// Initialize test registered resources
	s.fixtures.simpleRegisteredResource = &policy.RegisteredResource{
		Name: "simple-resource",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "test-value",
			},
		},
	}
}

// TestPDPSuite runs the test suite
func TestPDPSuite(t *testing.T) {
	suite.Run(t, new(PDPTestSuite))
}

// TestNewPolicyDecisionPoint tests the creation of a new PDP
func (s *PDPTestSuite) TestNewPolicyDecisionPoint() {
	f := s.fixtures

	tests := []struct {
		name                string
		attributes          []*policy.Attribute
		subjectMappings     []*policy.SubjectMapping
		registeredResources []*policy.RegisteredResource
		expectError         bool
	}{
		{
			name:                "valid initialization",
			attributes:          []*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr},
			subjectMappings:     []*policy.SubjectMapping{f.secretMapping, f.confidentialMapping, f.rndMapping},
			registeredResources: []*policy.RegisteredResource{f.simpleRegisteredResource},
			expectError:         false,
		},
		{
			name:            "nil attributes and nil subject mappings",
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
		{
			name:                "non-nil attributes and subject mappings but nil registered resources",
			attributes:          []*policy.Attribute{f.classificationAttr},
			subjectMappings:     []*policy.SubjectMapping{f.secretMapping},
			registeredResources: nil,
			expectError:         false,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			pdp, err := NewPolicyDecisionPoint(s.T().Context(), s.logger, tc.attributes, tc.subjectMappings, tc.registeredResources)

			if tc.expectError {
				s.Require().Error(err)
				s.Nil(pdp)
			} else {
				s.Require().NoError(err)
				s.NotNil(pdp)
			}
		})
	}
}

// Test_GetDecision_MultipleResources tests the GetDecision method with some generalized scenarios for multiple resources
func (s *PDPTestSuite) Test_GetDecision_MultipleResources() {
	f := s.fixtures

	// Create a PDP with relevant attributes and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr},
		[]*policy.SubjectMapping{f.secretMapping, f.topSecretMapping, f.confidentialMapping, f.engineeringMapping, f.financeMapping},
		[]*policy.RegisteredResource{},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Multiple resources and entitled actions/attributes - full access", func() {
		entity := s.createEntityWithProps("test-user-1", map[string]interface{}{
			"clearance":  "ts",
			"department": "engineering",
		})

		resources := createResourcePerFqn(testClassSecretFQN, testDeptEngineeringFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)
		s.Len(decision.Results, 2)

		expectedResults := map[string]bool{
			testClassSecretFQN:     true,
			testDeptEngineeringFQN: true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.True(result.Passed, "All data rules should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
		}
	})

	s.Run("Multiple resources and entitled actions/attributes of varied casing - full access", func() {
		entity := s.createEntityWithProps("test-user-1", map[string]interface{}{
			"clearance":  "ts",
			"department": "engineering",
		})
		secretFQN := strings.ToUpper(testClassSecretFQN)

		resources := createResourcePerFqn(secretFQN, testDeptEngineeringFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)
		s.Len(decision.Results, 2)

		expectedResults := map[string]bool{
			secretFQN:              true,
			testDeptEngineeringFQN: true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.True(result.Passed, "All data rules should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
		}
	})

	s.Run("Multiple resources and unentitled attributes - full denial", func() {
		entity := s.createEntityWithProps("test-user-2", map[string]interface{}{
			"clearance":  "confidential", // Not high enough for update on secret
			"department": "finance",      // Not engineering
		})

		resources := createResourcePerFqn(testClassSecretFQN, testDeptEngineeringFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionUpdate, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 2)

		expectedResults := map[string]bool{
			testClassSecretFQN:     false,
			testDeptEngineeringFQN: false,
		}

		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.False(result.Passed, "Data rules should not pass")
			s.Len(result.DataRuleResults, 1)
			s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
		}
	})

	s.Run("Multiple resources and unentitled actions - full denial", func() {
		entity := s.createEntityWithProps("test-user-3", map[string]interface{}{
			"clearance":  "topsecret",
			"department": "engineering",
		})

		resources := createResourcePerFqn(testDeptEngineeringFQN, testClassSecretFQN)

		// Get decision for delete action (not allowed by either attribute's subject mappings)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 2)

		expectedResults := map[string]bool{
			testDeptEngineeringFQN: false,
			testClassSecretFQN:     false,
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Multiple resources - partial access", func() {
		entity := s.createEntityWithProps("test-user-4", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering", // not finance
		})

		resources := createResourcePerFqn(testClassSecretFQN, testDeptFinanceFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // False because one resource is denied
		s.Len(decision.Results, 2)

		expectedResults := map[string]bool{
			testClassSecretFQN: true,
			testDeptFinanceFQN: false,
		}
		s.assertAllDecisionResults(decision, expectedResults)

		// Validate proper data rule results
		for _, result := range decision.Results {
			s.Len(result.DataRuleResults, 1)

			if result.ResourceID == testClassSecretFQN {
				s.True(result.Passed, "Secret should pass")
				s.Empty(result.DataRuleResults[0].EntitlementFailures)
			} else if result.ResourceID == testDeptFinanceFQN {
				s.False(result.Passed, "Finance should not pass")
				s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
			}
		}
	})
}

// Test_GetDecision_PartialActionEntitlement tests scenarios where actions only partially align with entitlements
func (s *PDPTestSuite) Test_GetDecision_PartialActionEntitlement() {
	f := s.fixtures

	// Define custom actions for testing
	testActionPrint := &policy.Action{Name: "print"}
	testActionView := &policy.Action{Name: "view"}
	testActionList := &policy.Action{Name: "list"}
	testActionSearch := &policy.Action{Name: "search"}

	// Create additional mappings for testing partial action scenarios
	printConfidentialMapping := createSimpleSubjectMapping(
		testClassConfidentialFQN,
		"confidential",
		[]*policy.Action{testActionRead, testActionPrint},
		".properties.clearance",
		[]string{"confidential"},
	)

	// Create a mapping with a comprehensive set of actions instead of using a wildcard
	allActionsPublicMapping := createSimpleSubjectMapping(
		testClassPublicFQN,
		"public",
		[]*policy.Action{
			testActionRead, testActionCreate, testActionUpdate, testActionDelete,
			testActionPrint, testActionView, testActionList, testActionSearch,
		},
		".properties.clearance",
		[]string{"public"},
	)

	// Create a view mapping for Project Alpha with view being a parent action of read and list
	viewProjectAlphaMapping := createSimpleSubjectMapping(
		testProjectAlphaFQN,
		"alpha",
		[]*policy.Action{testActionView},
		".properties.project",
		[]string{"alpha"},
	)

	// Create a PDP with relevant attributes and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.projectAttr},
		[]*policy.SubjectMapping{
			f.secretMapping, f.topSecretMapping, printConfidentialMapping, allActionsPublicMapping,
			f.engineeringMapping, f.financeMapping, viewProjectAlphaMapping,
		},
		[]*policy.RegisteredResource{},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Scenario 1: User has subset of requested actions", func() {
		// Entity with secret clearance - only entitled to read and update on secret
		entity := s.createEntityWithProps("user123", map[string]interface{}{
			"clearance": "secret",
		})

		// Resource to evaluate
		resources := createResourcePerFqn(testClassSecretFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, actionRead, resources)

		// Read shuld pass
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access) // Should be true because read is allowed
		s.Len(decision.Results, 1)

		// Create should fail
		decision, err = pdp.GetDecision(s.T().Context(), entity, actionCreate, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // Should be false because create is not allowed
		s.Len(decision.Results, 1)
	})

	s.Run("Scenario 2: User has overlapping action sets", func() {
		// Entity with both confidential clearance and finance department
		entity := s.createEntityWithProps("user456", map[string]interface{}{
			"clearance":  "confidential",
			"department": "finance",
		})

		combinedResource := createResource("combined-attr-resource", testClassConfidentialFQN, testDeptFinanceFQN)

		// Test read access - should be allowed by both attributes
		decision, err := pdp.GetDecision(s.T().Context(), entity, actionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)
		s.Len(decision.Results, 1)

		// Test create access - should be denied (confidential doesn't allow it)
		decision, err = pdp.GetDecision(s.T().Context(), entity, actionCreate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // Overall access is denied

		// Test print access - allowed by confidential but not by finance
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionPrint, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // Overall access is denied because one rule fails

		// Test update access - allowed by finance but not by confidential
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // Overall access is denied because one rule fails

		// Test delete access - denied by both
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionDelete, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
	})

	s.Run("Scenario 3: Action inheritance with partial permissions", func() {
		entity := s.createEntityWithProps("user789", map[string]interface{}{
			"project": "alpha",
		})

		resources := createResourcePerFqn(testProjectAlphaFQN)

		// Test view access - should be allowed
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionView, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// Test list access - should be denied
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionList, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)

		// Test search access - should be denied
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionSearch, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
	})

	s.Run("Scenario 4: Conflicting action policies across multiple attributes", func() {
		// Set up a PDP with the comprehensive actions public mapping and restricted mapping
		restrictedMapping := createSimpleSubjectMapping(
			testClassConfidentialFQN,
			"confidential",
			[]*policy.Action{testActionRead}, // Only read is allowed
			".properties.clearance",
			[]string{"restricted"},
		)

		classificationPDP, err := NewPolicyDecisionPoint(
			s.T().Context(),
			s.logger,
			[]*policy.Attribute{f.classificationAttr},
			[]*policy.SubjectMapping{allActionsPublicMapping, restrictedMapping},
			[]*policy.RegisteredResource{},
		)
		s.Require().NoError(err)
		s.Require().NotNil(classificationPDP)

		// Entity with both public and restricted clearance
		entity := s.createEntityWithProps("admin001", map[string]interface{}{
			"clearance": "restricted",
		})

		// Resource with restricted classification
		restrictedResources := createResourcePerFqn(testClassConfidentialFQN)

		// Test read access - should be allowed for restricted
		decision, err := classificationPDP.GetDecision(s.T().Context(), entity, actionRead, restrictedResources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// Test create access - should be denied for restricted despite comprehensive actions on public
		decision, err = classificationPDP.GetDecision(s.T().Context(), entity, actionCreate, restrictedResources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)

		// Test delete access - should be denied for restricted despite comprehensive actions on public
		decision, err = classificationPDP.GetDecision(s.T().Context(), entity, testActionDelete, restrictedResources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
	})
}

// Test_GetDecision_CombinedAttributeRules tests scenarios with combinations of different attribute rules on a single resource
func (s *PDPTestSuite) Test_GetDecision_CombinedAttributeRules_SingleResource() {
	f := s.fixtures

	// Create a PDP with all attribute types (HIERARCHY, ANY_OF, ALL_OF)
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr, f.projectAttr, f.platformAttr},
		[]*policy.SubjectMapping{
			f.topSecretMapping, f.secretMapping, f.confidentialMapping, f.publicMapping,
			f.engineeringMapping, f.financeMapping, f.rndMapping,
			f.usaMapping, f.ukMapping, f.projectAlphaMapping, f.platformCloudMapping,
		},
		[]*policy.RegisteredResource{},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("HIERARCHY + ANY_OF combined: Secret classification and Engineering department", func() {
		// Entity with proper entitlements for both attributes
		entity := s.createEntityWithProps("hier-any-user-1", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
		})

		// Single resource with both HIERARCHY (classification) and ANY_OF (department) attributes
		combinedResource := createResource("secret-engineering-resource", testClassSecretFQN, testDeptEngineeringFQN)

		// Test read access (both allow)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// Test create access (only engineering allows)
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionCreate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // False because both attributes need to pass

		// Test update access (only secret allows)
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // False because both attributes need to pass
	})

	s.Run("HIERARCHY + ALL_OF combined: Secret classification and USA country", func() {
		// Entity with proper entitlements for both attributes
		entity := s.createEntityWithProps("hier-all-user-1", map[string]interface{}{
			"clearance": "secret",
			"country":   []any{"us", "uk"},
		})

		// Single resource with both HIERARCHY and ALL_OF attributes
		combinedResource := createResource("secret-usa-resource", testClassSecretFQN, testCountryUSAFQN)

		// Test read access (both allow)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// Test update access (only secret allows, usa doesn't)
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // False because both attributes need to pass
	})

	s.Run("ANY_OF + ALL_OF combined: Engineering department and USA AND UK country", func() {
		// Entity with proper entitlements for both attributes
		entity := s.createEntityWithProps("any-all-user-1", map[string]interface{}{
			"department": "engineering",
			"country":    []any{"us", "uk"},
		})

		// Single resource with both ANY_OF and ALL_OF attributes
		combinedResource := createResource("engineering-usa-uk-resource", testDeptEngineeringFQN, testCountryUSAFQN, testCountryUKFQN)

		// Test read access (both allow)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// Test create access (only engineering allows)
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionCreate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // False because both attributes need to pass
	})

	s.Run("HIERARCHY + ANY_OF + ALL_OF combined - ALL_OF FAILURE", func() {
		// Entity with proper entitlements for all three attributes
		entity := s.createEntityWithProps("all-rules-user-1", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
			"country":    []any{"us"}, // does not have UK
		})

		// Single resource with all three attribute rule types, but missing one ALL_OF value FQN
		combinedResource := createResource("secret-engineering-usa-uk-resource", testClassSecretFQN, testDeptEngineeringFQN, testCountryUKFQN, testCountryUSAFQN)

		// Test read access (all three allow)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 1)

		// Drill down proper structure of denial
		resourceDecision := decision.Results[0]
		s.Require().False(resourceDecision.Passed)
		s.Equal("secret-engineering-usa-uk-resource", resourceDecision.ResourceID)
		s.Len(resourceDecision.DataRuleResults, 3)
		for _, ruleResult := range resourceDecision.DataRuleResults {
			switch ruleResult.RuleDefinition.GetFqn() {
			case testClassificationFQN:
				s.True(ruleResult.Passed)
			case testDepartmentFQN:
				s.True(ruleResult.Passed)
			case testCountryFQN:
				s.False(ruleResult.Passed)
			}
		}
	})

	s.Run("HIERARCHY + ANY_OF + ALL_OF combined - SUCCESS", func() {
		// Entity with proper entitlements for all three attributes
		entity := s.createEntityWithProps("all-rules-user-1", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
			"country":    []any{"us"},
		})

		// Single resource with all three attribute rule types
		combinedResource := createResource("secret-engineering-usa-resource", testClassSecretFQN, testDeptEngineeringFQN, testCountryUSAFQN)

		// Test read access (all three allow)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// No other action is permitted by all three attributes
		for _, action := range []string{actions.ActionNameCreate, actions.ActionNameUpdate, actions.ActionNameDelete} {
			d, err := pdp.GetDecision(s.T().Context(), entity, &policy.Action{Name: action}, []*authz.Resource{combinedResource})
			s.Require().NoError(err)
			s.Require().NotNil(d)
			s.False(d.Access, "Action %s should not be allowed", action)
		}
	})

	s.Run("HIERARCHY + ANY_OF + ALL_OF combined - ANY_OF FAILURE", func() {
		// Entity with only partial entitlements
		entity := s.createEntityWithProps("partial-entitlement-user", map[string]interface{}{
			"clearance":  "ts",
			"department": "finance", // not matching engineering
			"country":    []any{"us"},
		})

		// Resource with all three attribute types
		combinedResource := createResource("secret-engineering-usa-resource", testClassSecretFQN, testDeptEngineeringFQN, testCountryUSAFQN)

		// Test read access - should fail because department doesn't match
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)

		// Examine which attribute rule failed
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Equal("secret-engineering-usa-resource", onlyDecision.ResourceID)

		// Count passes and failures among data rules
		passCount := 0
		failCount := 0
		for _, dataRule := range onlyDecision.DataRuleResults {
			if dataRule.Passed {
				passCount++
			} else {
				failCount++
				// Check that failure is for country attribute
				s.Contains(dataRule.RuleDefinition.GetFqn(), "department")
			}
		}
		s.Equal(2, passCount, "Two attributes should pass")
		s.Equal(1, failCount, "One attribute should fail")
	})

	s.Run("Multiple attributes from different namespaces with different rules", func() {
		// Entity with cross-namespace entitlements
		entity := s.createEntityWithProps("cross-ns-rules-user", map[string]interface{}{
			"clearance": "secret",    // HIERARCHY rule
			"project":   "alpha",     // ANY_OF rule from secondary namespace
			"platform":  "cloud",     // ANY_OF rule from secondary namespace
			"country":   []any{"us"}, // ALL_OF rule
		})

		// Resource with attributes from different namespaces and with different rules
		complexResource := createResource("complex-multi-ns-resource",
			testClassSecretFQN,   // HIERARCHY rule
			testCountryUSAFQN,    // ALL_OF rule
			testProjectAlphaFQN,  // ANY_OF rule
			testPlatformCloudFQN, // ANY_OF rule
		)

		// Test read access (all four allow)
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{complexResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// Test delete access (only platform:cloud allows)
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionDelete, []*authz.Resource{complexResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access) // Overall fails because other attributes don't allow delete

		// Count how many attributes passed/failed for delete action
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		passCount := 0
		failCount := 0
		for _, dataRule := range onlyDecision.DataRuleResults {
			if dataRule.Passed {
				passCount++
				// Only the platform attribute should pass for delete
				s.Contains(dataRule.RuleDefinition.GetFqn(), "platform")
			} else {
				failCount++
			}
		}
		s.Equal(1, passCount, "One attribute should pass (platform:cloud)")
		s.Equal(3, failCount, "Three attributes should fail")
	})

	s.Run("Multiple HIERARCHY of duplicate same attribute value", func() {
		// Create a resource with multiple classifications (hierarchy rule)
		cascadingResource := &authz.Resource{
			EphemeralId: "classification-cascade-resource",
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{
					Fqns: []string{
						testClassSecretFQN,       // Secret classification
						testClassSecretFQN,       // duplicate
						testClassConfidentialFQN, // Confidential classification (lower than Secret)
						testClassConfidentialFQN, // second duplicate
					},
				},
			},
		}

		// Entity with secret clearance (which should also give access to confidential)
		entity := s.createEntityWithProps("secret-entity", map[string]interface{}{
			"clearance": "secret",
		})

		// Test read access
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access, "Entity with Secret clearance should have access to both Secret and Confidential")

		// Entity with confidential clearance (which should NOT give access to secret)
		entity = s.createEntityWithProps("confidential-entity", map[string]interface{}{
			"clearance": "confidential",
		})

		// Test read access
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access, "Entity with Confidential clearance should NOT have access to both classifications")

		// Verify which rule failed
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Len(onlyDecision.DataRuleResults, 1)
		ruleResult := onlyDecision.DataRuleResults[0]
		s.NotEmpty(ruleResult.EntitlementFailures)
		s.Equal(ruleResult.EntitlementFailures[0].AttributeValueFQN, testClassSecretFQN)
	})

	s.Run("Multiple HIERARCHY of different levels", func() {
		// Create a resource with multiple classifications (hierarchy rule)
		cascadingResource := createResource("classification-cascade-resource",
			testClassSecretFQN,       // Secret classification
			testClassConfidentialFQN, // Confidential classification (lower than Secret)
		)

		// Entity with topsecret clearance (which should also give access to confidential)
		entity := s.createEntityWithProps("secret-entity", map[string]interface{}{
			"clearance": "ts",
		})

		// Test read access
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access, "Entity with Secret clearance should have access to both Secret and Confidential")

		// Entity with confidential clearance (which should NOT give access to secret)
		entity = s.createEntityWithProps("confidential-entity", map[string]interface{}{
			"clearance": "confidential",
		})

		// Test read access
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access, "Entity with Confidential clearance should NOT have access to both classifications")

		// Verify which rule failed
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Len(onlyDecision.DataRuleResults, 1)
		ruleResult := onlyDecision.DataRuleResults[0]
		s.Len(ruleResult.EntitlementFailures, 1)
		s.Equal(ruleResult.EntitlementFailures[0].AttributeValueFQN, testClassSecretFQN)
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
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr, f.projectAttr, f.platformAttr},
		[]*policy.SubjectMapping{
			f.topSecretMapping, f.secretMapping, f.confidentialMapping, f.engineeringMapping, f.financeMapping,
			f.projectAlphaMapping, betaMapping, gammaMapping,
			f.platformCloudMapping, onPremMapping, hybridMapping,
			f.usaMapping,
		},
		[]*policy.RegisteredResource{},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Cross-namespace decision - full access", func() {
		entity := s.createEntityWithProps("cross-ns-user-1", map[string]interface{}{
			"clearance": "secret",
			"project":   "alpha",
		})

		// Two resources with each a different namespaced attribute value
		resources := createResourcePerFqn(testClassSecretFQN, testProjectAlphaFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

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

	s.Run("Cross-namespace decision - partial access", func() {
		// Entity with partial entitlements
		entity := s.createEntityWithProps("cross-ns-user-2", map[string]interface{}{
			"clearance": "secret",
			"project":   "beta", // Not alpha
			"platform":  "cloud",
		})

		// Resource with attribute values from two different namespaces
		resource := createResource("secret-alpha-cloud-fqn", testClassSecretFQN, testProjectAlphaFQN, testPlatformCloudFQN)

		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{resource})

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.Access)
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Len(onlyDecision.DataRuleResults, 3)
		for _, dataRule := range onlyDecision.DataRuleResults {
			if dataRule.Passed {
				isExpected := dataRule.RuleDefinition.GetFqn() == testPlatformFQN || dataRule.RuleDefinition.GetFqn() == testClassificationFQN
				s.True(isExpected, "Platform and classification should pass")
			} else {
				s.Equal(testProjectFQN, dataRule.RuleDefinition.GetFqn(), "Project should fail")
				s.Len(dataRule.EntitlementFailures, 1)
				s.Equal(testProjectAlphaFQN, dataRule.EntitlementFailures[0].AttributeValueFQN)
			}
		}
	})

	s.Run("Action permitted by one namespace mapping but not the other", func() {
		// Entity with entitlements for both namespaces
		entity := s.createEntityWithProps("cross-ns-user-3", map[string]interface{}{
			"clearance": "secret",
			"project":   "alpha",
			"platform":  "cloud",
		})

		resources := createResourcePerFqn(testClassSecretFQN, testProjectAlphaFQN)

		// Create action is permitted for project alpha but not for secret
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionCreate, resources)

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
		resources := createResourcePerFqn(
			testClassSecretFQN,
			testClassConfidentialFQN,
			testProjectAlphaFQN,
			testPlatformCloudFQN,
		)

		// Request for delete action - allowed only by platform cloud mapping
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)

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
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.Access)

		// The implementation treats this as a single resource with multiple rules
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Equal("combined-resource", onlyDecision.ResourceID)

		// Instead of checking by FQN, confirm all data rule results pass
		for _, dataRule := range onlyDecision.DataRuleResults {
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
		resources := createResourcePerFqn(
			testClassSecretFQN,     // base namespace
			testDeptEngineeringFQN, // base namespace
			testCountryUSAFQN,      // base namespace - ALL_OF
			testProjectAlphaFQN,    // secondary namespace
			testPlatformHybridFQN,  // secondary namespace
		)

		// Test read access - should pass for all namespaces
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

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
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)

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
		combinedResource := createResource("combined-multi-ns-resource",
			testClassConfidentialFQN, // base namespace
			testCountryUSAFQN,        // base namespace
			testProjectBetaFQN,       // secondary namespace
			testPlatformOnPremFQN,    // secondary namespace
		)

		// Test read access - should pass for this combined resource
		decision, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})

		s.Require().NoError(err)
		s.True(decision.Access)

		// The implementation treats this as a single resource with multiple rules
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Equal("combined-multi-ns-resource", onlyDecision.ResourceID)

		// Instead of checking FQN by FQN, verify all data rules pass
		s.Len(onlyDecision.DataRuleResults, 4) // Should have 4 data rules (one for each FQN)
		for _, dataRule := range onlyDecision.DataRuleResults {
			s.True(dataRule.Passed, "All data rules should pass for read action")
			s.Empty(dataRule.EntitlementFailures, "There should be no entitlement failures for read action")
		}

		// Test update access - should pass for all except country
		decision, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})

		// Overall access should be denied due to country not supporting update
		s.Require().NoError(err)
		s.False(decision.Access)
		s.Len(decision.Results, 1)
		onlyDecision = decision.Results[0]
		s.Equal("combined-multi-ns-resource", onlyDecision.ResourceID)

		// There should be 4 data rules, with some failing
		s.Len(onlyDecision.DataRuleResults, 4)

		// Count passes and failures
		passCount := 0
		failCount := 0
		for _, dataRule := range onlyDecision.DataRuleResults {
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
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.countryAttr},
		[]*policy.SubjectMapping{
			f.secretMapping, f.confidentialMapping, f.publicMapping,
			f.engineeringMapping, f.financeMapping, f.rndMapping,
			f.usaMapping,
		},
		[]*policy.RegisteredResource{},
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
		entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entity}, nil, false)

		s.Require().NoError(err)
		s.Require().NotNil(entitlements)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "test-entity-1")
		s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")

		// Verify entitlements for classification
		secretActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testClassSecretFQN]
		s.Require().NotNil(secretActions, "Secret classification entitlements should exist")
		s.Contains(actionNames(secretActions.GetActions()), actions.ActionNameRead)
		s.Contains(actionNames(secretActions.GetActions()), actions.ActionNameUpdate)

		// Verify entitlements for department
		engineeringActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testDeptEngineeringFQN]
		s.Require().NotNil(engineeringActions, "Engineering department entitlements should exist")
		s.Contains(actionNames(engineeringActions.GetActions()), actions.ActionNameRead)
		s.Contains(actionNames(engineeringActions.GetActions()), actions.ActionNameCreate)

		// Verify entitlements for country
		usaActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testCountryUSAFQN]
		s.Require().NotNil(usaActions, "USA country entitlements should exist")
		s.Contains(actionNames(usaActions.GetActions()), actions.ActionNameRead)
	})

	s.Run("Entity with no matching entitlements", func() {
		// Entity with no entitlements based on properties
		entity := s.createEntityWithProps("test-entity-2", map[string]interface{}{
			"clearance":  "unknown",
			"department": "unknown",
			"country":    []any{"unknown"},
		})

		// Get entitlements for this entity
		entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entity}, nil, false)

		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "test-entity-2")
		s.Require().NotNil(entityEntitlement, "Entity should be included in results even with no entitlements")
		s.Empty(entityEntitlement.GetActionsPerAttributeValueFqn(), "No attribute value FQNs should be mapped for this entity")
	})

	s.Run("Entity with partial entitlements", func() {
		// Entity with some entitlements
		entity := s.createEntityWithProps("test-entity-3", map[string]interface{}{
			"clearance":  "public",
			"department": "sales", // No mapping for sales
		})

		// Get entitlements for this entity
		entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entity}, nil, false)

		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "test-entity-3")
		s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")

		// Verify public classification entitlements exist
		s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), testClassPublicFQN, "Public classification entitlements should exist")
		publicActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testClassPublicFQN]
		s.Contains(actionNames(publicActions.GetActions()), actions.ActionNameRead)

		// Verify sales department entitlements do not exist
		s.NotContains(entityEntitlement.GetActionsPerAttributeValueFqn(), testDeptSalesFQN, "Sales department should not have entitlements")
	})

	s.Run("Multiple entities with various entitlements", func() {
		entityCases := []struct {
			name                 string
			entityRepresentation *entityresolutionV2.EntityRepresentation
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
				entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entityCase.entityRepresentation}, nil, false)

				s.Require().NoError(err)

				// Find the entity's entitlements
				entityEntitlement := findEntityEntitlements(entitlements, entityCase.name)
				s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")
				s.Require().Len(entityEntitlement.GetActionsPerAttributeValueFqn(), len(entityCase.expectedEntitlements), "Number of entitlements should match expected")

				// Verify expected entitlements exist
				for _, expectedFQN := range entityCase.expectedEntitlements {
					s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), expectedFQN)
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
		entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entity}, nil, true)

		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "hierarchy-test-entity")
		s.Require().NotNil(entityEntitlement)

		// With comprehensive hierarchy, the entity should have access to secret and all lower classifications
		s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), testClassSecretFQN)

		// The function populateLowerValuesIfHierarchy assumes the values in the hierarchy are arranged
		// in order from highest to lowest. In our test fixture, that means:
		// topsecret > secret > confidential > public

		// Secret clearance should give access to confidential and public (the items lower in the list)
		s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), testClassConfidentialFQN)
		s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), testClassPublicFQN)

		// But not to higher classifications
		s.NotContains(entityEntitlement.GetActionsPerAttributeValueFqn(), testClassTopSecretFQN)

		// Verify the actions for the lower levels match those granted to the secret level
		secretActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testClassSecretFQN]
		s.Require().NotNil(secretActions)

		confidentialActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testClassConfidentialFQN]
		s.Require().NotNil(confidentialActions)

		publicActions := entityEntitlement.GetActionsPerAttributeValueFqn()[testClassPublicFQN]
		s.Require().NotNil(publicActions)

		s.Len(secretActions.GetActions(), len(f.secretMapping.GetActions()))

		// The actions should be the same for all levels
		s.ElementsMatch(
			actionNames(secretActions.GetActions()),
			actionNames(confidentialActions.GetActions()),
			"Secret and confidential should have the same actions")

		s.ElementsMatch(
			actionNames(secretActions.GetActions()),
			actionNames(publicActions.GetActions()),
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
		entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entity}, filteredMappings, false)

		s.Require().NoError(err)

		// Find the entity's entitlements
		entityEntitlement := findEntityEntitlements(entitlements, "filtered-test-entity")
		s.Require().NotNil(entityEntitlement)

		// Should only have classification entitlements
		s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), testClassSecretFQN)

		// Should not have department or country entitlements
		s.NotContains(entityEntitlement.GetActionsPerAttributeValueFqn(), testDeptEngineeringFQN)
		s.NotContains(entityEntitlement.GetActionsPerAttributeValueFqn(), testCountryUSAFQN)
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
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{hierarchyAttribute},
		[]*policy.SubjectMapping{
			topMapping,
			upperMiddleMapping,
			middleMapping,
			lowerMiddleMapping,
			bottomMapping,
		},
		[]*policy.RegisteredResource{},
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	// Create an entity with every level in the hierarchy
	entity := s.createEntityWithProps("hierarchy-test-entity", map[string]interface{}{
		"levels": []any{"top", "upper-middle", "middle", "lower-middle", "bottom"},
	})

	// Get entitlements for this entity
	withComprehensiveHierarchy := true
	entitlements, err := pdp.GetEntitlements(s.T().Context(), []*entityresolutionV2.EntityRepresentation{entity}, nil, withComprehensiveHierarchy)
	s.Require().NoError(err)
	s.Require().NotNil(entitlements)

	// Find the entity's entitlements
	entityEntitlement := findEntityEntitlements(entitlements, "hierarchy-test-entity")
	s.Require().NotNil(entityEntitlement, "Entity entitlements should be found")
	s.Require().Len(entityEntitlement.GetActionsPerAttributeValueFqn(), 5, "Number of entitlements should match expected")
	s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), topValueFQN, "Top level should be present")
	s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), upperMiddleValueFQN, "Upper-middle level should be present")
	s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), middleValueFQN, "Middle level should be present")
	s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), lowerMiddleValueFQN, "Lower-middle level should be present")
	s.Contains(entityEntitlement.GetActionsPerAttributeValueFqn(), bottomValueFQN, "Bottom level should be present")

	// Verify actions for each level
	topActions := entityEntitlement.GetActionsPerAttributeValueFqn()[topValueFQN]
	s.Require().NotNil(topActions, "Top level actions should exist")
	s.Len(topActions.GetActions(), 1)
	s.Contains(actionNames(topActions.GetActions()), actions.ActionNameRead, "Top level should have read action")

	upperMiddleActions := entityEntitlement.GetActionsPerAttributeValueFqn()[upperMiddleValueFQN]
	s.Require().NotNil(upperMiddleActions, "Upper-middle level actions should exist")
	s.Len(upperMiddleActions.GetActions(), 2)
	upperMiddleActionNames := actionNames(upperMiddleActions.GetActions())
	s.Contains(upperMiddleActionNames, actions.ActionNameCreate, "Upper-middle level should have create action")
	s.Contains(upperMiddleActionNames, actions.ActionNameRead, "Upper-middle level should have read action")

	middleActions := entityEntitlement.GetActionsPerAttributeValueFqn()[middleValueFQN]
	s.Require().NotNil(middleActions, "Middle level actions should exist")
	s.Len(middleActions.GetActions(), 4)
	middleActionNames := actionNames(middleActions.GetActions())
	s.Contains(middleActionNames, actions.ActionNameUpdate, "Middle level should have update action")
	s.Contains(middleActionNames, actionNameTransmit, "Middle level should have transmit action")
	s.Contains(middleActionNames, actions.ActionNameCreate, "Middle level should have create action")
	s.Contains(middleActionNames, actions.ActionNameRead, "Middle level should have read action")

	lowerMiddleActions := entityEntitlement.GetActionsPerAttributeValueFqn()[lowerMiddleValueFQN]
	s.Require().NotNil(lowerMiddleActions, "Lower-middle level actions should exist")
	s.Len(lowerMiddleActions.GetActions(), 5)
	lowerMiddleActionNames := actionNames(lowerMiddleActions.GetActions())
	s.Contains(lowerMiddleActionNames, actions.ActionNameDelete, "Lower-middle level should have delete action")
	s.Contains(lowerMiddleActionNames, actions.ActionNameUpdate, "Lower-middle level should have update action")
	s.Contains(lowerMiddleActionNames, actions.ActionNameCreate, "Lower-middle level should have create action")
	s.Contains(lowerMiddleActionNames, actionNameTransmit, "Lower-middle level should have read action")
	s.Contains(lowerMiddleActionNames, actions.ActionNameRead, "Lower-middle level should have read action")

	bottomActions := entityEntitlement.GetActionsPerAttributeValueFqn()[bottomValueFQN]
	s.Require().NotNil(bottomActions, "Bottom level actions should exist")
	s.Len(bottomActions.GetActions(), 6)
	bottomActionNames := actionNames(bottomActions.GetActions())
	s.Contains(bottomActionNames, actions.ActionNameRead, "Bottom level should have read action")
	s.Contains(bottomActionNames, actions.ActionNameUpdate, "Bottom level should have update action")
	s.Contains(bottomActionNames, actions.ActionNameCreate, "Bottom level should have create action")
	s.Contains(bottomActionNames, actions.ActionNameDelete, "Bottom level should have delete action")
	s.Contains(bottomActionNames, actionNameTransmit, "Bottom level should have transmit action")
	s.Contains(bottomActionNames, customActionGather, "Bottom level should have gather action")
}

// Helper functions for all tests

// assertDecisionResult is a helper function to assert that a decision result for a given FQN matches the expected pass/fail state
func (s *PDPTestSuite) assertDecisionResult(decision *Decision, fqn string, shouldPass bool) {
	resourceDecision := findResourceDecision(decision, fqn)
	s.Require().NotNil(resourceDecision, "No result found for FQN: "+fqn)
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
func (s *PDPTestSuite) createEntityWithProps(entityID string, props map[string]interface{}) *entityresolutionV2.EntityRepresentation {
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

	return &entityresolutionV2.EntityRepresentation{
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

// createResourcePerFqn creates multiple resources, one for each attribute value FQN
func createResourcePerFqn(attributeValueFQNs ...string) []*authz.Resource {
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
		if e != nil && e.GetEphemeralId() == entityID {
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
