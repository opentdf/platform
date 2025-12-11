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

	// todo: add tests for allowDirectEntitlements = true behavior
	// using hard-coded false for now to keep existing tests passing
	allowDirectEntitlements = false
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

// Helper function to create registered resource value FQNs
func createRegisteredResourceValueFQN(name, value string) string {
	resourceValue := &identifier.FullyQualifiedRegisteredResourceValue{
		Name:  name,
		Value: value,
	}
	return resourceValue.FQN()
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

	// Registered resource value FQNs
	testNetworkPrivateFQN = createRegisteredResourceValueFQN("network", "private")
	testNetworkPublicFQN  = createRegisteredResourceValueFQN("network", "public")
)

// registered resource value FQNs using identifier package
var (
	// Classification values
	testClassSecretRegResFQN       = createRegisteredResourceValueFQN("classification", "secret")
	testClassConfidentialRegResFQN = createRegisteredResourceValueFQN("classification", "confidential")

	// Department values
	testDeptEngineeringRegResFQN = createRegisteredResourceValueFQN("department", "engineering")
	testDeptFinanceRegResFQN     = createRegisteredResourceValueFQN("department", "finance")
	testProjectAlphaRegResFQN    = createRegisteredResourceValueFQN("project", "alpha")
)

// Registered resource value FQNs using identifier package
// TODO: remove these and use the other ones above
var (
	regResValNoActionAttrValFQN                     string
	regResValSingleActionAttrValFQN                 string
	regResValDuplicateActionAttrValFQN              string
	regResValMultiActionSingleAttrValFQN            string
	regResValMultiActionMultiAttrValFQN             string
	regResValComprehensiveHierarchyActionAttrValFQN string
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
		classificationRegRes *policy.RegisteredResource
		deptRegRes           *policy.RegisteredResource
		networkRegRes        *policy.RegisteredResource // TODO: remove this and use the others that match test attributes
		countryRegRes        *policy.RegisteredResource
		projectRegRes        *policy.RegisteredResource
		platformRegRes       *policy.RegisteredResource

		// Test registered resources (TODO: remove these and use the ones above)
		regRes                                       *policy.RegisteredResource
		regResValNoActionAttrVal                     *policy.RegisteredResourceValue
		regResValSingleActionAttrVal                 *policy.RegisteredResourceValue
		regResValDuplicateActionAttrVal              *policy.RegisteredResourceValue
		regResValMultiActionSingleAttrVal            *policy.RegisteredResourceValue
		regResValMultiActionMultiAttrVal             *policy.RegisteredResourceValue
		regResValComprehensiveHierarchyActionAttrVal *policy.RegisteredResourceValue
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
		testClassTopSecretFQN,
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
		[]*policy.Action{testActionRead, testActionDelete},
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

	// Initialize registered resources
	s.fixtures.classificationRegRes = &policy.RegisteredResource{
		Name: "classification",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "topsecret",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassTopSecretFQN,
							Value: "topsecret",
						},
					},
				},
			},
			{
				Value: "secret",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassSecretFQN,
							Value: "secret",
						},
					},
					{
						Action: testActionUpdate,
						AttributeValue: &policy.Value{
							Fqn:   testClassSecretFQN,
							Value: "secret",
						},
					},
				},
			},
			{
				Value: "confidential",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassConfidentialFQN,
							Value: "confidential",
						},
					},
				},
			},
			{
				Value: "public",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassPublicFQN,
							Value: "public",
						},
					},
				},
			},
		},
	}

	s.fixtures.deptRegRes = &policy.RegisteredResource{
		Name: "department",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "rnd",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptRnDFQN,
							Value: "rnd",
						},
					},
					{
						Action: testActionUpdate,
						AttributeValue: &policy.Value{
							Fqn:   testDeptRnDFQN,
							Value: "rnd",
						},
					},
				},
			},
			{
				Value: "engineering",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptEngineeringFQN,
							Value: "engineering",
						},
					},
					{
						Action: testActionCreate,
						AttributeValue: &policy.Value{
							Fqn:   testDeptEngineeringFQN,
							Value: "engineering",
						},
					},
				},
			},
			{
				Value:                 "sales",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{},
			},
			{
				Value: "finance",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptFinanceFQN,
							Value: "finance",
						},
					},
					{
						Action: testActionUpdate,
						AttributeValue: &policy.Value{
							Fqn:   testDeptFinanceFQN,
							Value: "finance",
						},
					},
				},
			},
		},
	}

	s.fixtures.countryRegRes = &policy.RegisteredResource{
		Name: "country",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "usa",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testCountryUSAFQN,
							Value: "usa",
						},
					},
				},
			},
			{
				Value: "uk",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testCountryUKFQN,
							Value: "uk",
						},
					},
				},
			},
		},
	}

	s.fixtures.projectRegRes = &policy.RegisteredResource{
		Name: "project",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "alpha",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testProjectAlphaFQN,
							Value: "alpha",
						},
					},
					{
						Action: testActionCreate,
						AttributeValue: &policy.Value{
							Fqn:   testProjectAlphaFQN,
							Value: "alpha",
						},
					},
				},
			},
			{
				Value:                 "beta",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{},
			},
			{
				Value:                 "gamma",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{},
			},
		},
	}

	s.fixtures.platformRegRes = &policy.RegisteredResource{
		Name: "platform",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "cloud",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testPlatformCloudFQN,
							Value: "cloud",
						},
					},
					{
						Action: testActionDelete,
						AttributeValue: &policy.Value{
							Fqn:   testPlatformCloudFQN,
							Value: "cloud",
						},
					},
				},
			},
			{
				Value:                 "onprem",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{},
			},
			{
				Value:                 "hybrid",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{},
			},
		},
	}

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
	s.fixtures.networkRegRes = &policy.RegisteredResource{
		Name: "network",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "private",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassSecretFQN,
							Value: "secret",
						},
					},
					{
						Action: testActionUpdate,
						AttributeValue: &policy.Value{
							Fqn:   testClassSecretFQN,
							Value: "secret",
						},
					},
				},
			},
			{
				Value: "public",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassPublicFQN,
							Value: "public",
						},
					},
				},
			},
			{
				Value: "confidential",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassConfidentialFQN,
							Value: "confidential",
						},
					},
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptFinanceFQN,
							Value: "finance",
						},
					},
				},
			},
			{
				Value: "alpha",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testProjectAlphaFQN,
							Value: "alpha",
						},
					},
					{
						Action: testActionCreate,
						AttributeValue: &policy.Value{
							Fqn:   testProjectAlphaFQN,
							Value: "alpha",
						},
					},
				},
			},
		},
	}

	// Initialize test registered resources (TODO: replace with above real use cases)
	regResValNoActionAttrVal := &policy.RegisteredResourceValue{
		Value:                 "no-action-attr-val",
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{},
	}
	regResValSingleActionAttrVal := &policy.RegisteredResourceValue{
		Value: "single-action-attr-val",
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Action: testActionCreate,
				AttributeValue: &policy.Value{
					Fqn:   testClassSecretFQN,
					Value: "secret",
				},
			},
		},
	}
	regResValDuplicateActionAttrVal := &policy.RegisteredResourceValue{
		Value: "duplicate-action-attr-val",
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Action: testActionCreate,
				AttributeValue: &policy.Value{
					Fqn:   testClassSecretFQN,
					Value: "secret",
				},
			},
			{
				Action: testActionCreate,
				AttributeValue: &policy.Value{
					Fqn:   testClassSecretFQN,
					Value: "secret",
				},
			},
		},
	}
	regResValMultiActionSingleAttrVal := &policy.RegisteredResourceValue{
		Value: "multi-action-single-attr-val",
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Action: testActionCreate,
				AttributeValue: &policy.Value{
					Fqn:   testPlatformCloudFQN,
					Value: "cloud",
				},
			},
			{
				Action: testActionRead,
				AttributeValue: &policy.Value{
					Fqn:   testPlatformCloudFQN,
					Value: "cloud",
				},
			},
		},
	}
	regResValMultiActionMultiAttrVal := &policy.RegisteredResourceValue{
		Value: "multi-action-multi-attr-val",
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Action: testActionCreate,
				AttributeValue: &policy.Value{
					Fqn:   testClassSecretFQN,
					Value: "secret",
				},
			},
			{
				Action: testActionUpdate,
				AttributeValue: &policy.Value{
					Fqn:   testPlatformCloudFQN,
					Value: "cloud",
				},
			},
			{
				Action: testActionDelete,
				AttributeValue: &policy.Value{
					Fqn:   testPlatformCloudFQN,
					Value: "cloud",
				},
			},
		},
	}
	regResValComprehensiveHierarchyActionAttrVal := &policy.RegisteredResourceValue{
		Value: "comprehensive-hierarchy-action-attr-val",
		ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Action: testActionRead,
				AttributeValue: &policy.Value{
					Fqn:   testClassSecretFQN,
					Value: "secret",
				},
			},
		},
	}

	regRes := &policy.RegisteredResource{
		Name: "test-res",
		Values: []*policy.RegisteredResourceValue{
			regResValNoActionAttrVal,
			regResValSingleActionAttrVal,
			regResValDuplicateActionAttrVal,
			regResValMultiActionSingleAttrVal,
			regResValMultiActionMultiAttrVal,
			regResValComprehensiveHierarchyActionAttrVal,
		},
	}

	s.fixtures.regRes = regRes
	s.fixtures.regResValNoActionAttrVal = regResValNoActionAttrVal
	s.fixtures.regResValSingleActionAttrVal = regResValSingleActionAttrVal
	s.fixtures.regResValDuplicateActionAttrVal = regResValDuplicateActionAttrVal
	s.fixtures.regResValMultiActionSingleAttrVal = regResValMultiActionSingleAttrVal
	s.fixtures.regResValMultiActionMultiAttrVal = regResValMultiActionMultiAttrVal
	s.fixtures.regResValComprehensiveHierarchyActionAttrVal = regResValComprehensiveHierarchyActionAttrVal

	regResValNoActionAttrValFQN = createRegisteredResourceValueFQN(regRes.GetName(), regResValNoActionAttrVal.GetValue())
	regResValSingleActionAttrValFQN = createRegisteredResourceValueFQN(regRes.GetName(), regResValSingleActionAttrVal.GetValue())
	regResValDuplicateActionAttrValFQN = createRegisteredResourceValueFQN(regRes.GetName(), regResValDuplicateActionAttrVal.GetValue())
	regResValMultiActionSingleAttrValFQN = createRegisteredResourceValueFQN(regRes.GetName(), regResValMultiActionSingleAttrVal.GetValue())
	regResValMultiActionMultiAttrValFQN = createRegisteredResourceValueFQN(regRes.GetName(), regResValMultiActionMultiAttrVal.GetValue())
	regResValComprehensiveHierarchyActionAttrValFQN = createRegisteredResourceValueFQN(regRes.GetName(), regResValComprehensiveHierarchyActionAttrVal.GetValue())
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
			registeredResources: []*policy.RegisteredResource{f.regRes},
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
			pdp, err := NewPolicyDecisionPoint(
				s.T().Context(), s.logger, tc.attributes, tc.subjectMappings, tc.registeredResources, allowDirectEntitlements)

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
		[]*policy.SubjectMapping{f.secretMapping, f.topSecretMapping, f.confidentialMapping, f.publicMapping, f.rndMapping, f.engineeringMapping, f.financeMapping},
		[]*policy.RegisteredResource{f.classificationRegRes, f.deptRegRes},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Multiple resources and entitled actions/attributes - full access", func() {
		entity := s.createEntityWithProps("test-user-1", map[string]interface{}{
			"clearance":  "ts",
			"department": "engineering",
		})

		resources := createResourcePerFqn(
			testClassSecretFQN, testDeptEngineeringFQN,
			testClassSecretRegResFQN, testDeptEngineeringRegResFQN,
		)

		decision, entitlements, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testClassSecretFQN:           true,
			testDeptEngineeringFQN:       true,
			testClassSecretRegResFQN:     true,
			testDeptEngineeringRegResFQN: true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.True(result.Entitled, "All data rules should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
		}

		// Verify entitlements are returned correctly
		s.Require().NotNil(entitlements, "Entitlements should not be nil")
		s.Contains(entitlements, testClassTopSecretFQN, "Should be entitled to topsecret classification based on clearance 'ts'")
		s.Contains(entitlements, testDeptEngineeringFQN, "Should be entitled to engineering department")

		// Verify the testActionRead is in the entitled actions for these attribute values
		s.Require().Contains(entitlements[testClassTopSecretFQN], testActionRead, "Should have read action for topsecret classification")
		s.Require().Contains(entitlements[testDeptEngineeringFQN], testActionRead, "Should have read action for engineering department")
		s.Require().Contains(entitlements[testDeptEngineeringFQN], testActionCreate, "Should have create action for engineering department")
	})

	s.Run("Multiple resources and entitled actions/attributes of varied casing - full access", func() {
		entity := s.createEntityWithProps("test-user-1", map[string]interface{}{
			"clearance":  "ts",
			"department": "engineering",
		})
		secretFQN := strings.ToUpper(testClassSecretFQN)
		secretRegResFQN := strings.ToUpper(testClassSecretRegResFQN)

		resources := createResourcePerFqn(secretFQN, testDeptEngineeringFQN, secretRegResFQN, testDeptEngineeringRegResFQN)

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			secretFQN:                    true,
			testDeptEngineeringFQN:       true,
			secretRegResFQN:              true,
			testDeptEngineeringRegResFQN: true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.True(result.Entitled, "All data rules should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
		}
	})

	s.Run("Multiple resources and unentitled attributes - full denial", func() {
		entity := s.createEntityWithProps("test-user-2", map[string]interface{}{
			"clearance":  "confidential", // Not high enough for update on secret
			"department": "finance",      // Not engineering
		})

		resources := createResourcePerFqn(
			testClassSecretFQN, testDeptEngineeringFQN,
			testClassSecretRegResFQN, testDeptEngineeringRegResFQN,
		)

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionUpdate, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testClassSecretFQN:           false,
			testDeptEngineeringFQN:       false,
			testClassSecretRegResFQN:     false,
			testDeptEngineeringRegResFQN: false,
		}

		s.assertAllDecisionResults(decision, expectedResults)
		for idx, result := range decision.Results {
			s.False(result.Entitled, "Data rules should not pass")
			// Only expect rule results if the rule was evaluated, which doesn't happen for early
			// failures within action-attribute-value mismatches with the requested action
			if idx < 3 {
				s.Len(result.DataRuleResults, 1)
				s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
			}
		}
	})

	s.Run("Multiple resources and unentitled actions - full denial", func() {
		entity := s.createEntityWithProps("test-user-3", map[string]interface{}{
			"clearance":  "topsecret",
			"department": "engineering",
		})

		resources := createResourcePerFqn(
			testDeptEngineeringFQN, testClassSecretFQN,
			testDeptEngineeringRegResFQN, testClassSecretRegResFQN)

		// Get decision for delete action (not allowed by either attribute's subject mappings)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testDeptEngineeringFQN:       false,
			testClassSecretFQN:           false,
			testDeptEngineeringRegResFQN: false,
			testClassSecretRegResFQN:     false,
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Multiple resources - partial access", func() {
		entity := s.createEntityWithProps("test-user-4", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering", // not finance
		})

		resources := createResourcePerFqn(
			testClassSecretFQN, testDeptFinanceFQN,
			testClassSecretRegResFQN, testDeptFinanceRegResFQN,
		)

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // False because one resource is denied
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testClassSecretFQN:       true,
			testDeptFinanceFQN:       false,
			testClassSecretRegResFQN: true,
			testDeptFinanceRegResFQN: false,
		}
		s.assertAllDecisionResults(decision, expectedResults)

		// Validate proper data rule results
		for _, result := range decision.Results {
			s.Len(result.DataRuleResults, 1)

			switch result.ResourceID {
			case testClassSecretFQN:
				s.True(result.Entitled, "Secret should pass")
				s.Empty(result.DataRuleResults[0].EntitlementFailures)
			case testDeptFinanceFQN:
				s.False(result.Entitled, "Finance should not pass")
				s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
			}
		}
	})

	s.Run("Multiple registered resources - entity has full access", func() {
		entity := s.createEntityWithProps("topsecret-rnd-user", map[string]interface{}{
			"clearance":  "ts",
			"department": "rnd",
		})

		rndDeptRegResFQN := createRegisteredResourceValueFQN(f.deptRegRes.GetName(), f.deptRegRes.GetValues()[0].GetValue())
		topsecretClassRegResFQN := createRegisteredResourceValueFQN(f.classificationRegRes.GetName(), f.classificationRegRes.GetValues()[0].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: rndDeptRegResFQN,
				},
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: topsecretClassRegResFQN,
				},
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 2)

		foundRnd := false
		foundTopSecret := false
		for _, result := range decision.Results {
			s.True(result.Entitled, "All registered resource value access requests should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
			switch result.ResourceName {
			case rndDeptRegResFQN:
				foundRnd = true
			case topsecretClassRegResFQN:
				foundTopSecret = true
			default:
				s.Failf("Unexpected resource name: %s", result.ResourceName)
			}
		}
		s.True(foundRnd)
		s.True(foundTopSecret)
	})

	s.Run("Multiple registered resources and entitled actions/attributes of varied casing - full access", func() {
		entity := s.createEntityWithProps("topsecret-rnd-user", map[string]interface{}{
			"clearance":  "ts",
			"department": "rnd",
		})

		rndDeptRegResFQN := createRegisteredResourceValueFQN(f.deptRegRes.GetName(), f.deptRegRes.GetValues()[0].GetValue())
		topsecretClassRegResFQN := createRegisteredResourceValueFQN(f.classificationRegRes.GetName(), f.classificationRegRes.GetValues()[0].GetValue())

		// Upper case both registered resource value FQNs for assurance FQNs will be case-normalized
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: strings.ToUpper(rndDeptRegResFQN),
				},
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: strings.ToUpper(topsecretClassRegResFQN),
				},
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 2)

		foundRnd := false
		foundTopSecret := false
		for _, result := range decision.Results {
			s.True(result.Entitled, "All registered resource value access requests should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
			switch result.ResourceName {
			case rndDeptRegResFQN:
				foundRnd = true
			case topsecretClassRegResFQN:
				foundTopSecret = true
			default:
				s.Failf("Unexpected resource name: %s", result.ResourceName)
			}
		}
		s.True(foundRnd)
		s.True(foundTopSecret)
	})

	s.Run("Multiple registered resources and unentitled attributes - full denial", func() {
		entity := s.createEntityWithProps("test-user-2", map[string]interface{}{
			"clearance":  "confidential", // Not high enough for read on topsecret
			"department": "finance",      // Not rnd
		})

		rndDeptRegResFQN := createRegisteredResourceValueFQN(f.deptRegRes.GetName(), f.deptRegRes.GetValues()[0].GetValue())
		topsecretClassRegResFQN := createRegisteredResourceValueFQN(f.classificationRegRes.GetName(), f.classificationRegRes.GetValues()[0].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: rndDeptRegResFQN,
				},
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: topsecretClassRegResFQN,
				},
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 2)

		foundRnd := false
		foundTopSecret := false
		for _, result := range decision.Results {
			s.False(result.Entitled, "All registered resource access requests should fail")
			s.Len(result.DataRuleResults, 1)
			s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
			switch result.ResourceName {
			case rndDeptRegResFQN:
				foundRnd = true
			case topsecretClassRegResFQN:
				foundTopSecret = true
			default:
				s.Failf("Unexpected resource name: %s", result.ResourceName)
			}
		}
		s.True(foundRnd)
		s.True(foundTopSecret)
	})

	s.Run("Multiple registered resources and unentitled actions - full denial", func() {
		entity := s.createEntityWithProps("test-user-2", map[string]interface{}{
			"clearance":  "ts",  // subject mapping permits read
			"department": "rnd", // subject mapping permits read/update
		})

		rndDeptRegResFQN := createRegisteredResourceValueFQN(f.deptRegRes.GetName(), f.deptRegRes.GetValues()[0].GetValue())
		topsecretClassRegResFQN := createRegisteredResourceValueFQN(f.classificationRegRes.GetName(), f.classificationRegRes.GetValues()[0].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: rndDeptRegResFQN,
				},
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: topsecretClassRegResFQN,
				},
			},
		}

		unentitledAction := testActionDelete
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, unentitledAction, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 2)

		foundRnd := false
		foundTopSecret := false
		for _, result := range decision.Results {
			s.False(result.Entitled, "All registered resource access requests should fail")
			switch result.ResourceName {
			case rndDeptRegResFQN:
				foundRnd = true
			case topsecretClassRegResFQN:
				foundTopSecret = true
			default:
				s.Failf("Unexpected resource name: %s", result.ResourceName)
			}
		}
		s.True(foundRnd)
		s.True(foundTopSecret)
	})

	s.Run("Multiple registered resources and unentitled actions - partial action-specific denial", func() {
		entity := s.createEntityWithProps("test-user-2", map[string]interface{}{
			"clearance":  "ts",  // subject mapping permits read
			"department": "rnd", // subject mapping permits read/update
		})

		rndDeptRegResFQN := createRegisteredResourceValueFQN(f.deptRegRes.GetName(), f.deptRegRes.GetValues()[0].GetValue())
		topsecretClassRegResFQN := createRegisteredResourceValueFQN(f.classificationRegRes.GetName(), f.classificationRegRes.GetValues()[0].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: rndDeptRegResFQN,
				},
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: topsecretClassRegResFQN,
				},
			},
		}

		partiallyEntitledAction := testActionUpdate
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, partiallyEntitledAction, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 2)

		foundRnd := false
		foundTopSecret := false
		for _, result := range decision.Results {
			switch result.ResourceName {
			case rndDeptRegResFQN:
				s.Len(result.DataRuleResults, 1)
				s.True(result.DataRuleResults[0].Passed)
				s.Empty(result.DataRuleResults[0].EntitlementFailures)
				foundRnd = true
			case topsecretClassRegResFQN:
				foundTopSecret = true
			default:
				s.Failf("Unexpected resource name: %s", result.ResourceName)
			}
		}
		s.True(foundRnd)
		s.True(foundTopSecret)
	})

	s.Run("Multiple registered resources - partial attribute-specific denial", func() {
		entity := s.createEntityWithProps("test-user-4", map[string]interface{}{
			"clearance":  "confidential", // not top secret
			"department": "rnd",
		})

		rndDeptRegResFQN := createRegisteredResourceValueFQN(f.deptRegRes.GetName(), f.deptRegRes.GetValues()[0].GetValue())
		topsecretClassRegResFQN := createRegisteredResourceValueFQN(f.classificationRegRes.GetName(), f.classificationRegRes.GetValues()[0].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: rndDeptRegResFQN,
				},
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: topsecretClassRegResFQN,
				},
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 2)

		foundRnd := false
		foundTopSecret := false
		for _, result := range decision.Results {
			s.Len(result.DataRuleResults, 1)

			switch result.ResourceName {
			case rndDeptRegResFQN:
				s.True(result.DataRuleResults[0].Passed)
				s.Empty(result.DataRuleResults[0].EntitlementFailures)
				foundRnd = true
			case topsecretClassRegResFQN:
				s.False(result.DataRuleResults[0].Passed)
				s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
				foundTopSecret = true
			default:
				s.Failf("Unexpected resource name: %s", result.ResourceName)
			}
		}
		s.True(foundRnd)
		s.True(foundTopSecret)
	})
}

func (s *PDPTestSuite) Test_GetDecision_ReturnsDecisionRelatedEntitlements() {
	f := s.fixtures

	// Create PDP with test fixtures
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr},
		[]*policy.SubjectMapping{f.topSecretMapping, f.engineeringMapping},
		[]*policy.RegisteredResource{},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	entity := s.createEntityWithProps("test-user-entitlements", map[string]interface{}{
		"clearance":  "ts",
		"department": "engineering",
	})

	resources := createResourcePerFqn(testClassSecretFQN, testDeptEngineeringFQN)

	decision, entitlements, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.True(decision.AllPermitted, "Entity should have access")

	s.Require().NotNil(entitlements, "Entitlements should not be nil")

	// The entitlement on the same attribute should be returned, but in this case, is hierarchically higher
	s.Require().Contains(entitlements, testClassTopSecretFQN)
	s.NotContains(entitlements, testClassSecretFQN)

	// The entity should be entitled to engineering department
	s.Require().Contains(entitlements, testDeptEngineeringFQN)

	// Actions match expected
	topsecretActions := entitlements[testClassTopSecretFQN]
	s.Require().NotNil(topsecretActions)
	s.Require().Len(topsecretActions, 1)
	s.Equal(actions.ActionNameRead, topsecretActions[0].GetName())

	engineeringActions := entitlements[testDeptEngineeringFQN]
	s.Require().NotNil(engineeringActions)
	s.Require().Len(engineeringActions, 2)

	// Check both read and create actions are present (order may vary)
	actionNames := make(map[string]bool)
	for _, action := range engineeringActions {
		actionNames[action.GetName()] = true
	}
	s.True(actionNames[actions.ActionNameRead])
	s.True(actionNames[actions.ActionNameCreate])
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

	readConfidentialRegRes := &policy.RegisteredResource{
		Name: "docs",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "confidential-read",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassConfidentialFQN,
							Value: "confidential",
						},
					},
				},
			},
		},
	}

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
		[]*policy.Action{testActionView, actionCreate, actionRead},
		".properties.project",
		[]string{"alpha"},
	)

	// Create a PDP with relevant attributes and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr, f.projectAttr, f.countryAttr},
		[]*policy.SubjectMapping{
			f.secretMapping, f.topSecretMapping, printConfidentialMapping, allActionsPublicMapping,
			f.engineeringMapping, f.financeMapping, viewProjectAlphaMapping, f.ukMapping,
		},
		[]*policy.RegisteredResource{
			f.classificationRegRes, f.deptRegRes, f.projectRegRes,
			readConfidentialRegRes, f.countryRegRes,
		},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("User has subset of requested actions", func() {
		// Entity with secret clearance - only entitled to read and update on secret
		entity := s.createEntityWithProps("user123", map[string]interface{}{
			"clearance": "secret",
		})

		// Resource to evaluate
		resources := createResourcePerFqn(testClassSecretFQN, testClassSecretRegResFQN)

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, actionRead, resources)

		// Read should pass
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted) // Should be true because read is allowed
		s.Len(decision.Results, 2)

		// Create should fail
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, actionCreate, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // Should be false because create is not allowed
		s.Len(decision.Results, 2)
	})

	s.Run("User has overlapping action sets", func() {
		// Entity with both confidential clearance and finance department
		entity := s.createEntityWithProps("user456", map[string]interface{}{
			"clearance":  "confidential",
			"department": "finance",
		})

		combinedResource := createAttributeValueResource("combined-attr-resource", testClassConfidentialFQN, testDeptFinanceFQN)
		testClassConfidentialRegResResource := createRegisteredResource(testClassConfidentialRegResFQN, testClassConfidentialRegResFQN)
		testDeptFinanceRegResResource := createRegisteredResource(testDeptFinanceRegResFQN, testDeptFinanceRegResFQN)

		// Test read access - should be allowed by all attributes
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, actionRead, []*authz.Resource{combinedResource, testClassConfidentialRegResResource, testDeptFinanceRegResResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 3)

		// Test create access - should be denied (confidential doesn't allow it)
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, actionCreate, []*authz.Resource{combinedResource, testClassConfidentialRegResResource, testDeptFinanceRegResResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // Overall access is denied

		// Test print access - allowed by confidential but not by finance
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionPrint, []*authz.Resource{combinedResource, testClassConfidentialRegResResource, testDeptFinanceRegResResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // Overall access is denied because one rule fails

		// Test update access - allowed by finance but not by confidential
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource, testClassConfidentialRegResResource, testDeptFinanceRegResResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // Overall access is denied because one rule fails

		// Test delete access - denied by both
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionDelete, []*authz.Resource{combinedResource, testClassConfidentialRegResResource, testDeptFinanceRegResResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
	})

	s.Run("Action inheritance with partial permissions", func() {
		entity := s.createEntityWithProps("user789", map[string]interface{}{
			"project": "alpha",
		})

		// testProjectAlphaRegResFQN - read/create,
		resources := createResourcePerFqn(testProjectAlphaFQN, testProjectAlphaRegResFQN)

		// Test view access - should be denied as view action not supported by registered resource
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionView, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test list access - should be denied
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionList, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test search access - should be denied
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionSearch, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test read access - should be allowed
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, actionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// Test create access - should be allowed
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, actionCreate, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
	})

	s.Run("Conflicting action policies across multiple attributes", func() {
		// Set up a PDP with the comprehensive actions public mapping and restricted mapping
		restrictedMapping := createSimpleSubjectMapping(
			testClassConfidentialFQN,
			"confidential",
			[]*policy.Action{testActionRead}, // Only read is allowed
			".properties.clearance",
			[]string{"restricted"},
		)
		restrictedRegRes := &policy.RegisteredResource{
			Name: "confidential-restricted",
			Values: []*policy.RegisteredResourceValue{
				{
					Value: "restricted-read",
					ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
						{
							Action: testActionRead,
							AttributeValue: &policy.Value{
								Fqn:   testClassConfidentialFQN,
								Value: "confidential",
							},
						},
					},
				},
			},
		}

		classificationPDP, err := NewPolicyDecisionPoint(
			s.T().Context(),
			s.logger,
			[]*policy.Attribute{f.classificationAttr},
			[]*policy.SubjectMapping{allActionsPublicMapping, restrictedMapping},
			[]*policy.RegisteredResource{f.classificationRegRes, restrictedRegRes},
			allowDirectEntitlements,
		)
		s.Require().NoError(err)
		s.Require().NotNil(classificationPDP)

		// Entity with both public and restricted clearance
		entity := s.createEntityWithProps("admin001", map[string]interface{}{
			"clearance": "restricted",
		})

		// Resource with restricted classification
		restrictedResources := createResourcePerFqn(testClassConfidentialFQN, testClassConfidentialRegResFQN)

		// Test read access - should be allowed for restricted
		decision, _, err := classificationPDP.GetDecision(s.T().Context(), entity, actionRead, restrictedResources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// Test create access - should be denied for restricted despite comprehensive actions on public
		decision, _, err = classificationPDP.GetDecision(s.T().Context(), entity, actionCreate, restrictedResources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test delete access - should be denied for restricted despite comprehensive actions on public
		decision, _, err = classificationPDP.GetDecision(s.T().Context(), entity, testActionDelete, restrictedResources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
	})

	s.Run("Requested entitled action (on hierarchical attribute) not supported by registered resource fails", func() {
		entity := s.createEntityWithProps("conf-printer-reader", map[string]interface{}{
			"clearance": "confidential",
		})

		readConfidentialRegResFQN := createRegisteredResourceValueFQN(readConfidentialRegRes.GetName(), readConfidentialRegRes.GetValues()[0].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: readConfidentialRegResFQN,
				},
			},
		}

		// Test print access - should be denied because RR action-attribute-value does not support it despite
		// entity's entitlement to the action on the attribute
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionPrint, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test unentitled action - should be denied
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionList, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test read access - should be allowed
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
	})

	s.Run("Requested entitled action (on any_of attribute) not supported by registered resource fails", func() {
		entity := s.createEntityWithProps("country-uk-reader-deleter", map[string]interface{}{
			"country": []any{"uk"},
		})

		readCountryUKRegResFQN := createRegisteredResourceValueFQN(f.countryRegRes.GetName(), f.countryRegRes.GetValues()[1].GetValue())

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: readCountryUKRegResFQN,
				},
			},
		}

		// Test delete access - should be denied because RR action-attribute-value does not support it despite
		// entity's entitlement to the action on the attribute
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test unentitled action - should be denied
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionList, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

		// Test read access - should be allowed
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
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
		allowDirectEntitlements,
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
		combinedResource := createAttributeValueResource("secret-engineering-resource", testClassSecretFQN, testDeptEngineeringFQN)

		// Test read access (both allow)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// Test create access (only engineering allows)
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionCreate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // False because both attributes need to pass

		// Test update access (only secret allows)
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // False because both attributes need to pass
	})

	s.Run("HIERARCHY + ALL_OF combined: Secret classification and USA country", func() {
		// Entity with proper entitlements for both attributes
		entity := s.createEntityWithProps("hier-all-user-1", map[string]interface{}{
			"clearance": "secret",
			"country":   []any{"us", "uk"},
		})

		// Single resource with both HIERARCHY and ALL_OF attributes
		combinedResource := createAttributeValueResource("secret-usa-resource", testClassSecretFQN, testCountryUSAFQN)

		// Test read access (both allow)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// Test update access (only secret allows, usa doesn't)
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // False because both attributes need to pass
	})

	s.Run("ANY_OF + ALL_OF combined: Engineering department and USA AND UK country", func() {
		// Entity with proper entitlements for both attributes
		entity := s.createEntityWithProps("any-all-user-1", map[string]interface{}{
			"department": "engineering",
			"country":    []any{"us", "uk"},
		})

		// Single resource with both ANY_OF and ALL_OF attributes
		combinedResource := createAttributeValueResource("engineering-usa-uk-resource", testDeptEngineeringFQN, testCountryUSAFQN, testCountryUKFQN)

		// Test read access (both allow)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// Test create access (only engineering allows)
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionCreate, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // False because both attributes need to pass
	})

	s.Run("HIERARCHY + ANY_OF + ALL_OF combined - ALL_OF FAILURE", func() {
		// Entity with proper entitlements for all three attributes
		entity := s.createEntityWithProps("all-rules-user-1", map[string]interface{}{
			"clearance":  "secret",
			"department": "engineering",
			"country":    []any{"us"}, // does not have UK
		})

		// Single resource with all three attribute rule types, but missing one ALL_OF value FQN
		combinedResource := createAttributeValueResource("secret-engineering-usa-uk-resource", testClassSecretFQN, testDeptEngineeringFQN, testCountryUKFQN, testCountryUSAFQN)

		// Test read access (all three allow)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 1)

		// Drill down proper structure of denial
		resourceDecision := decision.Results[0]
		s.Require().False(resourceDecision.Entitled)
		s.Equal("secret-engineering-usa-uk-resource", resourceDecision.ResourceID)
		s.Len(resourceDecision.DataRuleResults, 3)
		for _, ruleResult := range resourceDecision.DataRuleResults {
			switch ruleResult.Attribute.GetFqn() {
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
		combinedResource := createAttributeValueResource("secret-engineering-usa-resource", testClassSecretFQN, testDeptEngineeringFQN, testCountryUSAFQN)

		// Test read access (all three allow)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// No other action is permitted by all three attributes
		for _, action := range []string{actions.ActionNameCreate, actions.ActionNameUpdate, actions.ActionNameDelete} {
			d, _, err := pdp.GetDecision(s.T().Context(), entity, &policy.Action{Name: action}, []*authz.Resource{combinedResource})
			s.Require().NoError(err)
			s.Require().NotNil(d)
			s.False(d.AllPermitted, "Action %s should not be allowed", action)
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
		combinedResource := createAttributeValueResource("secret-engineering-usa-resource", testClassSecretFQN, testDeptEngineeringFQN, testCountryUSAFQN)

		// Test read access - should fail because department doesn't match
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)

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
				s.Contains(dataRule.Attribute.GetFqn(), "department")
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
		complexResource := createAttributeValueResource("complex-multi-ns-resource",
			testClassSecretFQN,   // HIERARCHY rule
			testCountryUSAFQN,    // ALL_OF rule
			testProjectAlphaFQN,  // ANY_OF rule
			testPlatformCloudFQN, // ANY_OF rule
		)

		// Test read access (all four allow)
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{complexResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

		// Test delete access (only platform:cloud allows)
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionDelete, []*authz.Resource{complexResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // Overall fails because other attributes don't allow delete

		// Count how many attributes passed/failed for delete action
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		passCount := 0
		failCount := 0
		for _, dataRule := range onlyDecision.DataRuleResults {
			if dataRule.Passed {
				passCount++
				// Only the platform attribute should pass for delete
				s.Contains(dataRule.Attribute.GetFqn(), "platform")
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
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted, "Entity with Secret clearance should have access to both Secret and Confidential")

		// Entity with confidential clearance (which should NOT give access to secret)
		entity = s.createEntityWithProps("confidential-entity", map[string]interface{}{
			"clearance": "confidential",
		})

		// Test read access
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "Entity with Confidential clearance should NOT have access to both classifications")

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
		cascadingResource := createAttributeValueResource("classification-cascade-resource",
			testClassSecretFQN,       // Secret classification
			testClassConfidentialFQN, // Confidential classification (lower than Secret)
		)

		// Entity with topsecret clearance (which should also give access to confidential)
		entity := s.createEntityWithProps("secret-entity", map[string]interface{}{
			"clearance": "ts",
		})

		// Test read access
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted, "Entity with Secret clearance should have access to both Secret and Confidential")

		// Entity with confidential clearance (which should NOT give access to secret)
		entity = s.createEntityWithProps("confidential-entity", map[string]interface{}{
			"clearance": "confidential",
		})

		// Test read access
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{cascadingResource})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted, "Entity with Confidential clearance should NOT have access to both classifications")

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
		allowDirectEntitlements,
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

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
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
		resource := createAttributeValueResource("secret-alpha-cloud-fqn", testClassSecretFQN, testProjectAlphaFQN, testPlatformCloudFQN)

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{resource})

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 1)
		onlyDecision := decision.Results[0]
		s.Len(onlyDecision.DataRuleResults, 3)
		for _, dataRule := range onlyDecision.DataRuleResults {
			if dataRule.Passed {
				isExpected := dataRule.Attribute.GetFqn() == testPlatformFQN || dataRule.Attribute.GetFqn() == testClassificationFQN
				s.True(isExpected, "Platform and classification should pass")
			} else {
				s.Equal(testProjectFQN, dataRule.Attribute.GetFqn(), "Project should fail")
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
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionCreate, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
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
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
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
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)

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
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		s.Require().NoError(err)
		s.True(decision.AllPermitted)
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
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionDelete, resources)

		// Overall access should be denied
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
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
		combinedResource := createAttributeValueResource("combined-multi-ns-resource",
			testClassConfidentialFQN, // base namespace
			testCountryUSAFQN,        // base namespace
			testProjectBetaFQN,       // secondary namespace
			testPlatformOnPremFQN,    // secondary namespace
		)

		// Test read access - should pass for this combined resource
		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, []*authz.Resource{combinedResource})

		s.Require().NoError(err)
		s.True(decision.AllPermitted)

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
		decision, _, err = pdp.GetDecision(s.T().Context(), entity, testActionUpdate, []*authz.Resource{combinedResource})

		// Overall access should be denied due to country not supporting update
		s.Require().NoError(err)
		s.False(decision.AllPermitted)
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

func (s *PDPTestSuite) Test_GetDecisionRegisteredResource_MultipleResources() {
	f := s.fixtures

	regResS3BucketEntity := &policy.RegisteredResource{
		Name: "s3-bucket",
		Values: []*policy.RegisteredResourceValue{
			{
				Value: "ts-engineering",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassTopSecretFQN,
							Value: "topsecret",
						},
					},
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptEngineeringFQN,
							Value: "engineering",
						},
					},
				},
			},
			{
				Value: "confidential-finance",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassConfidentialFQN,
							Value: "confidential",
						},
					},
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptFinanceFQN,
							Value: "finance",
						},
					},
				},
			},
			{
				Value: "secret-engineering",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testClassSecretFQN,
							Value: "secret",
						},
					},
					{
						Action: testActionRead,
						AttributeValue: &policy.Value{
							Fqn:   testDeptEngineeringFQN,
							Value: "engineering",
						},
					},
				},
			},
		},
	}

	// Create a PDP with relevant attributes and mappings
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr, f.departmentAttr},
		[]*policy.SubjectMapping{f.secretMapping, f.topSecretMapping, f.confidentialMapping, f.publicMapping, f.engineeringMapping, f.financeMapping},
		[]*policy.RegisteredResource{f.networkRegRes, regResS3BucketEntity},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Multiple resources and entitled actions/attributes - full access", func() {
		entityRegResFQN := createRegisteredResourceValueFQN(regResS3BucketEntity.GetName(), "ts-engineering")
		resources := createResourcePerFqn(testClassSecretFQN, testDeptEngineeringFQN, testNetworkPrivateFQN, testNetworkPublicFQN)

		decision, _, err := pdp.GetDecisionRegisteredResource(s.T().Context(), entityRegResFQN, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testClassSecretFQN:     true,
			testDeptEngineeringFQN: true,
			testNetworkPrivateFQN:  true,
			testNetworkPublicFQN:   true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.True(result.Entitled, "All data rules should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
		}
	})

	s.Run("Multiple resources and entitled actions/attributes of varied casing - full access", func() {
		entityRegResFQN := createRegisteredResourceValueFQN(regResS3BucketEntity.GetName(), "ts-engineering")
		secretFQN := strings.ToUpper(testClassSecretFQN)
		networkPrivateFQN := strings.ToUpper(testNetworkPrivateFQN)

		resources := createResourcePerFqn(secretFQN, testDeptEngineeringFQN, networkPrivateFQN, testNetworkPublicFQN)

		decision, _, err := pdp.GetDecisionRegisteredResource(s.T().Context(), entityRegResFQN, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.True(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			secretFQN:              true,
			testDeptEngineeringFQN: true,
			networkPrivateFQN:      true,
			testNetworkPublicFQN:   true,
		}
		s.assertAllDecisionResults(decision, expectedResults)
		for _, result := range decision.Results {
			s.True(result.Entitled, "All data rules should pass")
			s.Len(result.DataRuleResults, 1)
			s.Empty(result.DataRuleResults[0].EntitlementFailures)
		}
	})

	s.Run("Multiple resources and unentitled attributes - full denial", func() {
		entityRegResFQN := createRegisteredResourceValueFQN(regResS3BucketEntity.GetName(), "confidential-finance")

		resources := createResourcePerFqn(testClassSecretFQN, testDeptEngineeringFQN, testNetworkPrivateFQN, testNetworkPublicFQN)

		decision, _, err := pdp.GetDecisionRegisteredResource(s.T().Context(), entityRegResFQN, testActionUpdate, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testClassSecretFQN:     false,
			testDeptEngineeringFQN: false,
			testNetworkPrivateFQN:  false,
			testNetworkPublicFQN:   false,
		}

		s.assertAllDecisionResults(decision, expectedResults)
		for idx, result := range decision.Results {
			s.False(result.Entitled, "Data rules should not pass")
			// Only expect rule results if the rule was evaluated, which doesn't happen for early
			// failures within action-attribute-value mismatches with the requested action
			if idx < 3 {
				s.Len(result.DataRuleResults, 1)
				s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
			}
		}
	})

	s.Run("Multiple resources and unentitled actions - full denial", func() {
		entityRegResFQN := createRegisteredResourceValueFQN(regResS3BucketEntity.GetName(), "ts-engineering")

		resources := createResourcePerFqn(testDeptEngineeringFQN, testClassSecretFQN, testNetworkPrivateFQN, testNetworkPublicFQN)

		// Get decision for delete action (not allowed by either attribute's subject mappings)
		decision, _, err := pdp.GetDecisionRegisteredResource(s.T().Context(), entityRegResFQN, testActionDelete, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testDeptEngineeringFQN: false,
			testClassSecretFQN:     false,
			testNetworkPrivateFQN:  false,
			testNetworkPublicFQN:   false,
		}
		s.assertAllDecisionResults(decision, expectedResults)
	})

	s.Run("Multiple resources - partial access", func() {
		entityRegResFQN := createRegisteredResourceValueFQN(regResS3BucketEntity.GetName(), "secret-engineering")

		resources := createResourcePerFqn(testClassSecretFQN, testDeptFinanceFQN, testNetworkPrivateFQN, testNetworkPublicFQN)

		decision, _, err := pdp.GetDecisionRegisteredResource(s.T().Context(), entityRegResFQN, testActionRead, resources)

		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted) // False because one resource is denied
		s.Len(decision.Results, 4)

		expectedResults := map[string]bool{
			testClassSecretFQN:    true,
			testDeptFinanceFQN:    false,
			testNetworkPrivateFQN: true,
			testNetworkPublicFQN:  true,
		}
		s.assertAllDecisionResults(decision, expectedResults)

		// Validate proper data rule results
		for _, result := range decision.Results {
			s.Len(result.DataRuleResults, 1)

			switch result.ResourceID {
			case testClassSecretFQN:
				s.True(result.Entitled, "Secret should pass")
				s.Empty(result.DataRuleResults[0].EntitlementFailures)
			case testDeptFinanceFQN:
				s.False(result.Entitled, "Finance should not pass")
				s.NotEmpty(result.DataRuleResults[0].EntitlementFailures)
			}
		}
	})
}

func (s *PDPTestSuite) Test_GetDecisionRegisteredResource_PartialActionEntitlement() {
	s.T().Skip("TODO")
}

func (s *PDPTestSuite) Test_GetDecisionRegisteredResource_CombinedAttributeRules_SingleResource() {
	s.T().Skip("TODO")
}

func (s *PDPTestSuite) Test_GetDecisionRegisteredResource_AcrossNamespaces() {
	s.T().Skip("TODO")
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
		allowDirectEntitlements,
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
		allowDirectEntitlements,
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

func (s *PDPTestSuite) Test_GetEntitlementsRegisteredResource() {
	f := s.fixtures

	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr},
		[]*policy.SubjectMapping{},
		[]*policy.RegisteredResource{f.regRes},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Invalid registered resource value FQN format", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			"invalid_fqn_format",
			false,
		)

		s.Require().Error(err)
		s.Require().ErrorIs(err, identifier.ErrInvalidFQNFormat)
		s.Require().Nil(entitlements)
	})

	s.Run("Valid but non-existent registered resource value FQN", func() {
		validButNonexistentFQN := createRegisteredResourceValueFQN("test-res-not-exist", "test-value-not-exist")
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			validButNonexistentFQN,
			false,
		)

		s.Require().Error(err)
		s.Require().ErrorIs(err, ErrInvalidResource)
		s.Require().Nil(entitlements)
	})

	s.Run("no action attribute values", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			regResValNoActionAttrValFQN,
			false,
		)

		s.Require().NoError(err)
		s.Require().NotNil(entitlements)
		s.Require().Len(entitlements, 1)
		entityEntitlement := entitlements[0]
		s.Equal(regResValNoActionAttrValFQN, entityEntitlement.GetEphemeralId())
		s.Require().Empty(entityEntitlement.GetActionsPerAttributeValueFqn())
	})

	s.Run("single action attribute value", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			regResValSingleActionAttrValFQN,
			false,
		)

		s.Require().NoError(err)
		s.Require().NotNil(entitlements)
		s.Require().Len(entitlements, 1)
		entityEntitlement := entitlements[0]
		s.Equal(regResValSingleActionAttrValFQN, entityEntitlement.GetEphemeralId())
		actionsPerAttrValueFQN := entityEntitlement.GetActionsPerAttributeValueFqn()
		s.Require().Len(actionsPerAttrValueFQN, 1)
		actionsList := actionsPerAttrValueFQN[testClassSecretFQN]
		s.ElementsMatch(actionNames(actionsList.GetActions()), []string{actions.ActionNameCreate})
	})

	s.Run("duplicate action attribute values", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			regResValDuplicateActionAttrValFQN,
			false,
		)
		s.Require().NoError(err)
		s.Require().NotNil(entitlements)
		s.Require().Len(entitlements, 1)
		entityEntitlement := entitlements[0]
		s.Equal(regResValDuplicateActionAttrValFQN, entityEntitlement.GetEphemeralId())
		actionsPerAttrValueFQN := entityEntitlement.GetActionsPerAttributeValueFqn()
		s.Require().Len(actionsPerAttrValueFQN, 1)
		actionsList := actionsPerAttrValueFQN[testClassSecretFQN]
		s.ElementsMatch(actionNames(actionsList.GetActions()), []string{actions.ActionNameCreate})
	})

	s.Run("multiple actions single attribute value", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			regResValMultiActionSingleAttrValFQN,
			false,
		)

		s.Require().NoError(err)
		s.Require().NotNil(entitlements)
		s.Require().Len(entitlements, 1)
		entityEntitlement := entitlements[0]
		s.Equal(regResValMultiActionSingleAttrValFQN, entityEntitlement.GetEphemeralId())
		actionsPerAttrValueFQN := entityEntitlement.GetActionsPerAttributeValueFqn()
		s.Require().Len(actionsPerAttrValueFQN, 1)
		actionsList := actionsPerAttrValueFQN[testPlatformCloudFQN]
		s.ElementsMatch(actionNames(actionsList.GetActions()), []string{actions.ActionNameCreate, actions.ActionNameRead})
	})

	s.Run("multiple actions multiple attribute values", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			regResValMultiActionMultiAttrValFQN,
			false,
		)

		s.Require().NoError(err)
		s.Require().NotNil(entitlements)
		s.Require().Len(entitlements, 1)
		entityEntitlement := entitlements[0]
		s.Equal(regResValMultiActionMultiAttrValFQN, entityEntitlement.GetEphemeralId())
		actionsPerAttrValueFQN := entityEntitlement.GetActionsPerAttributeValueFqn()
		s.Require().Len(actionsPerAttrValueFQN, 2)
		secretActionsList := actionsPerAttrValueFQN[testClassSecretFQN]
		s.ElementsMatch(actionNames(secretActionsList.GetActions()), []string{actions.ActionNameCreate})
		cloudActionsList := actionsPerAttrValueFQN[testPlatformCloudFQN]
		s.ElementsMatch(actionNames(cloudActionsList.GetActions()), []string{actions.ActionNameUpdate, actions.ActionNameDelete})
	})

	s.Run("comprehensive hierarchy action attribute value", func() {
		entitlements, err := pdp.GetEntitlementsRegisteredResource(
			s.T().Context(),
			regResValComprehensiveHierarchyActionAttrValFQN,
			true, // With comprehensive hierarchy
		)

		s.Require().NoError(err)
		s.Require().NotNil(entitlements)
		s.Require().Len(entitlements, 1)
		entityEntitlement := entitlements[0]
		s.Equal(regResValComprehensiveHierarchyActionAttrValFQN, entityEntitlement.GetEphemeralId())

		actionsPerAttributeValueFQN := entityEntitlement.GetActionsPerAttributeValueFqn()

		// secret should give access to all lower classifications (secret > confidential > public)
		s.Require().Len(actionsPerAttributeValueFQN, 3)
		s.Contains(actionsPerAttributeValueFQN, testClassSecretFQN)
		s.Contains(actionsPerAttributeValueFQN, testClassConfidentialFQN)
		s.Contains(actionsPerAttributeValueFQN, testClassPublicFQN)

		// but not higher classifications
		s.NotContains(actionsPerAttributeValueFQN, testClassTopSecretFQN)

		// all actions for secret, confidential, and public should be the same
		secretActions := actionsPerAttributeValueFQN[testClassSecretFQN]
		confidentialActions := actionsPerAttributeValueFQN[testClassConfidentialFQN]
		publicActions := actionsPerAttributeValueFQN[testClassPublicFQN]
		expectedActionNames := []string{actions.ActionNameRead}
		s.ElementsMatch(actionNames(secretActions.GetActions()), expectedActionNames)
		s.ElementsMatch(actionNames(confidentialActions.GetActions()), expectedActionNames)
		s.ElementsMatch(actionNames(publicActions.GetActions()), expectedActionNames)
	})
}

// createAttributeValueResource creates a resource with attribute values
func createAttributeValueResource(ephemeralID string, attributeValueFQNs ...string) *authz.Resource {
	return &authz.Resource{
		EphemeralId: ephemeralID,
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{
				Fqns: attributeValueFQNs,
			},
		},
	}
}

// createRegisteredResource creates a resource with registered resource value FQN
func createRegisteredResource(ephemeralID string, registeredResourceValueFQN string) *authz.Resource {
	return &authz.Resource{
		EphemeralId: ephemeralID,
		Resource: &authz.Resource_RegisteredResourceValueFqn{
			RegisteredResourceValueFqn: registeredResourceValueFQN,
		},
	}
}

// createResourcePerFqn creates multiple resources, one for each attribute value FQN
func createResourcePerFqn(attributeValueFQNs ...string) []*authz.Resource {
	resources := make([]*authz.Resource, len(attributeValueFQNs))
	for i, fqn := range attributeValueFQNs {
		// Use the FQN itself as the resource ID instead of a generic "ephemeral-id-X"
		resourceID := fqn
		if _, err := identifier.Parse[*identifier.FullyQualifiedRegisteredResourceValue](fqn); err == nil {
			// FQN is a registered resource value
			resources[i] = createRegisteredResource(resourceID, fqn)
		} else {
			// FQN is an attribute value
			resources[i] = createAttributeValueResource(resourceID, fqn)
		}
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

func (s *PDPTestSuite) Test_GetDecision_NonExistentAttributeFQN() {
	f := s.fixtures

	// Create a PDP with only classification attribute
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr},
		[]*policy.SubjectMapping{f.secretMapping, f.topSecretMapping},
		[]*policy.RegisteredResource{},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Single resource with non-existent FQN - should DENY", func() {
		entity := s.createEntityWithProps("test-user", map[string]interface{}{
			"clearance": "ts",
		})

		nonExistentFQN := createAttrValueFQN(testBaseNamespace, "space", "cosmic")
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{nonExistentFQN},
					},
				},
				EphemeralId: "resource-with-missing-fqn",
			},
		}

		decision, entitlements, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		// No error, but deny decision
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 1)

		// Resource is denied
		s.False(decision.Results[0].Entitled)
		s.Equal("resource-with-missing-fqn", decision.Results[0].ResourceID)
		s.Require().NotNil(entitlements)
	})

	s.Run("Multiple resources with mixed valid/invalid FQNs - fine-grained denial", func() {
		entity := s.createEntityWithProps("test-user", map[string]interface{}{
			"clearance": "ts",
		})

		// Create resources: 2 valid, 1 with non-existent FQN
		nonExistentFQNBadDefinition := createAttrValueFQN(testBaseNamespace, "severity", "high")
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassSecretFQN}, // Valid - entity is entitled
					},
				},
				EphemeralId: "valid-resource-1",
			},
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{nonExistentFQNBadDefinition}, // Invalid - doesn't exist
					},
				},
				EphemeralId: "invalid-resource-2",
			},
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassTopSecretFQN}, // Valid - entity is entitled
					},
				},
				EphemeralId: "valid-resource-3",
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		// Should NOT error
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 3)

		// Verify individual resource decisions
		expectedResults := map[string]bool{
			"valid-resource-1":   true,  // Entitled
			"invalid-resource-2": false, // Denied due to non-existent FQN
			"valid-resource-3":   true,  // Entitled
		}

		for _, result := range decision.Results {
			expected, exists := expectedResults[result.ResourceID]
			s.Require().True(exists, "Unexpected resource ID: %s", result.ResourceID)
			s.Equal(expected, result.Entitled, "Entitlement mismatch for resource: %s", result.ResourceID)
		}
	})
}

func (s *PDPTestSuite) Test_GetDecision_PartialFQNsInResource() {
	f := s.fixtures

	// Create a PDP with classification attribute (hierarchical rule)
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr},
		[]*policy.SubjectMapping{f.secretMapping, f.topSecretMapping, f.confidentialMapping},
		[]*policy.RegisteredResource{},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Resource with mix of valid and invalid FQNs - DENIED", func() {
		entity := s.createEntityWithProps("test-user", map[string]interface{}{
			"clearance": "ts",
		})

		nonExistentValueFQNBadNamespace := createAttrValueFQN("does.notexist", "classification", "cosmic")
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{
							testClassSecretFQN,              // Valid
							nonExistentValueFQNBadNamespace, // Non-existent - causes DENY
							testClassTopSecretFQN,           // Valid
						},
					},
				},
				EphemeralId: "mixed-fqn-resource",
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		// No error, but deny decision
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.Len(decision.Results, 1)

		s.False(decision.AllPermitted)
		s.False(decision.Results[0].Entitled)
	})
}

func (s *PDPTestSuite) Test_GetDecisionRegisteredResource_NonExistentFQN() {
	f := s.fixtures

	// Create a PDP with classification attribute
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{f.classificationAttr},
		[]*policy.SubjectMapping{f.secretMapping},
		[]*policy.RegisteredResource{f.classificationRegRes}, // Only classification registered resource
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("Registered resource with non-existent FQN - should DENY", func() {
		entity := s.createEntityWithProps("test-user", map[string]interface{}{
			"clearance": "secret",
		})

		nonExistentRegResFQN := createRegisteredResourceValueFQN("special-system", "classified")
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: nonExistentRegResFQN,
				},
				EphemeralId: "missing-reg-res",
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		// No error, but deny decision
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 1)

		// Resource is denied
		s.False(decision.Results[0].Entitled)
		s.Equal("missing-reg-res", decision.Results[0].ResourceID)
		s.Equal(nonExistentRegResFQN, decision.Results[0].ResourceName)
	})

	s.Run("Mix of valid registered resource and non-existent FQN - fine-grained", func() {
		entity := s.createEntityWithProps("test-user", map[string]interface{}{
			"clearance": "secret",
		})

		nonExistentRegResFQN := createRegisteredResourceValueFQN("secret-system", "classified")
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: testClassSecretRegResFQN, // Valid
				},
				EphemeralId: "valid-reg-res",
			},
			{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: nonExistentRegResFQN, // Non-existent
				},
				EphemeralId: "invalid-reg-res",
			},
		}

		decision, _, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		// Should NOT error
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 2)

		// Verify individual decisions
		for _, result := range decision.Results {
			switch result.ResourceID {
			case "valid-reg-res":
				s.True(result.Entitled)
			case "invalid-reg-res":
				s.False(result.Entitled)
			default:
				s.Failf("Unexpected resource ID: %s", result.ResourceID)
			}
		}
	})
}

func (s *PDPTestSuite) Test_GetDecision_NoPolicies() {
	// Empty PDP with no attributes, subject mappings, or registered resources
	pdp, err := NewPolicyDecisionPoint(
		s.T().Context(),
		s.logger,
		[]*policy.Attribute{},
		[]*policy.SubjectMapping{},
		[]*policy.RegisteredResource{},
		allowDirectEntitlements,
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("No policy found - should DENY all resources", func() {
		entity := s.createEntityWithProps("test-user", map[string]interface{}{
			"clearance": "ts",
		})

		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassSecretFQN},
					},
				},
				EphemeralId: "resource-1",
			},
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassTopSecretFQN},
					},
				},
				EphemeralId: "resource-2",
			},
		}

		decision, entitlements, err := pdp.GetDecision(s.T().Context(), entity, testActionRead, resources)

		// No error, but deny decision
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.False(decision.AllPermitted)
		s.Len(decision.Results, 2)

		for _, result := range decision.Results {
			s.False(result.Entitled)
		}

		// Empty entitlements without available policy
		s.Require().NotNil(entitlements)
		s.Empty(entitlements)
	})
}

func (s *PDPTestSuite) Test_GetDecision_DirectEntitlements() {
	ctx := s.T().Context()

	attr1 := &policy.Attribute{
		Fqn:  "https://demo.com/attr/adhoc",
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Fqn:   "https://demo.com/attr/adhoc/value/direct_entitlement_1",
				Value: "direct_entitlement_1",
			},
		},
	}
	attr1ValueFQN := attr1.GetValues()[0].GetFqn()

	attr2 := &policy.Attribute{
		Fqn:  "https://demo.com/attr/adhoc_2",
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Fqn:   "https://demo.com/attr/adhoc_2/value/direct_entitlement_2",
				Value: "direct_entitlement_2",
			},
		},
	}
	attr2ValueFQN := attr2.GetValues()[0].GetFqn()

	resAttr1ValueFqn := createAttributeValueResource(attr1ValueFQN, attr1ValueFQN)
	resAttr2ValueFqn := createAttributeValueResource(attr2ValueFQN, attr2ValueFQN)

	pdp, err := NewPolicyDecisionPoint(
		ctx,
		s.logger,
		[]*policy.Attribute{attr1, attr2},
		[]*policy.SubjectMapping{},
		[]*policy.RegisteredResource{},
		true, // Allow direct entitlements
	)
	s.Require().NoError(err)
	s.Require().NotNil(pdp)

	s.Run("entitled to all resources", func() {
		entityRep := &entityresolutionV2.EntityRepresentation{
			DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
				{
					AttributeValueFqn: attr1ValueFQN,
					Actions:           []string{actions.ActionNameCreate, actions.ActionNameDelete},
				},
				{
					AttributeValueFqn: attr2ValueFQN,
					Actions:           []string{actions.ActionNameCreate, actions.ActionNameRead},
				},
			},
		}

		decision, entitlements, err := pdp.GetDecision(ctx, entityRep, testActionCreate, []*authz.Resource{
			resAttr1ValueFqn,
			resAttr2ValueFqn,
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.Require().NotNil(entitlements)

		s.Require().Contains(entitlements, attr1ValueFQN)
		s.Require().Contains(entitlements, attr2ValueFQN)
		s.Require().Contains(entitlements[attr1ValueFQN], testActionCreate)
		s.Require().Contains(entitlements[attr2ValueFQN], testActionCreate)

		s.assertAllDecisionResults(decision, map[string]bool{
			attr1ValueFQN: true,
			attr2ValueFQN: true,
		})
	})

	s.Run("entitled to some resources", func() {
		entityRep := &entityresolutionV2.EntityRepresentation{
			DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
				{
					AttributeValueFqn: attr1ValueFQN,
					Actions:           []string{actions.ActionNameCreate, actions.ActionNameUpdate},
				},
			},
		}

		decision, entitlements, err := pdp.GetDecision(ctx, entityRep, testActionCreate, []*authz.Resource{
			resAttr1ValueFqn,
			resAttr2ValueFqn,
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.Require().NotNil(entitlements)

		s.Require().Contains(entitlements, attr1ValueFQN)
		s.Require().Contains(entitlements[attr1ValueFQN], testActionCreate)

		s.assertAllDecisionResults(decision, map[string]bool{
			attr1ValueFQN: true,
			// not entitled to FQN
			attr2ValueFQN: false,
		})
	})

	s.Run("entitled to no resources", func() {
		entityRep := &entityresolutionV2.EntityRepresentation{
			DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
				{
					AttributeValueFqn: attr1ValueFQN,
					Actions:           []string{actions.ActionNameCreate, actions.ActionNameRead},
				},
			},
		}

		decision, entitlements, err := pdp.GetDecision(ctx, entityRep, testActionDelete, []*authz.Resource{
			resAttr1ValueFqn,
			resAttr2ValueFqn,
		})
		s.Require().NoError(err)
		s.Require().NotNil(decision)
		s.Require().NotNil(entitlements)

		s.Require().Contains(entitlements, attr1ValueFQN)
		s.Require().Contains(entitlements[attr1ValueFQN], testActionCreate)

		s.assertAllDecisionResults(decision, map[string]bool{
			// entitled to FQN, but not action
			attr1ValueFQN: false,
			// not entitled to FQN
			attr2ValueFQN: false,
		})
	})
}

// Helper functions for all tests

// assertDecisionResult is a helper function to assert that a decision result for a given FQN matches the expected pass/fail state
func (s *PDPTestSuite) assertDecisionResult(decision *Decision, fqn string, shouldPass bool) {
	resourceDecision := findResourceDecision(decision, fqn)
	s.Require().NotNil(resourceDecision, "No result found for FQN: "+fqn)
	s.Equal(shouldPass, resourceDecision.Entitled, "Unexpected result for FQN %s. Expected (%t), got (%t)", fqn, shouldPass, resourceDecision.Entitled)
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
