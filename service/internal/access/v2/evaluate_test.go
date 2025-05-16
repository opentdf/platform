package access

import (
	"testing"

	"github.com/stretchr/testify/suite"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/actions"
)

// Constants for namespaces and attribute FQNs
const (
	// Base namespaces
	baseNamespace     = "https://namespace.com"
	classificationFQN = baseNamespace + "/attr/classification"
	departmentFQN     = baseNamespace + "/attr/department"
	projectFQN        = baseNamespace + "/attr/project"

	// Classification values
	classTopSecretFQN    = classificationFQN + "/value/topsecret"
	classSecretFQN       = classificationFQN + "/value/secret"
	classConfidentialFQN = classificationFQN + "/value/confidential"
	classRestrictedFQN   = classificationFQN + "/value/restricted"
	classPublicFQN       = classificationFQN + "/value/public"

	// Department values
	deptFinanceFQN   = departmentFQN + "/value/finance"
	deptMarketingFQN = departmentFQN + "/value/marketing"
	deptLegalFQN     = departmentFQN + "/value/legal"

	// Project values
	projectJusticeLeagueFQN = projectFQN + "/value/justiceleague"
	projectAvengersFQN      = projectFQN + "/value/avengers"
	projectXmenFQN          = projectFQN + "/value/xmen"
	projectFantasicFourFQN  = projectFQN + "/value/fantasticfour"
)

var (
	// Actions
	actionRead   = &policy.Action{Name: actions.ActionNameRead}
	actionCreate = &policy.Action{Name: actions.ActionNameCreate}
)

// EvaluateTestSuite is a test suite for the evaluate.go file functions
type EvaluateTestSuite struct {
	suite.Suite
	logger *logger.Logger
	action *policy.Action

	// Common test data
	hierarchicalClassAttr *policy.Attribute
	allOfProjectAttr      *policy.Attribute
	anyOfDepartmentAttr   *policy.Attribute
	accessibleAttrValues  map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
}

func (s *EvaluateTestSuite) SetupTest() {
	s.logger = logger.CreateTestLogger()
	s.action = actionRead

	// Setup classification attribute (HIERARCHY)
	s.hierarchicalClassAttr = &policy.Attribute{
		Fqn:  classificationFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			// highest in hierarchy
			{Fqn: classTopSecretFQN, Value: "topsecret"},
			{Fqn: classSecretFQN, Value: "secret"},
			{Fqn: classConfidentialFQN, Value: "confidential"},
			{Fqn: classRestrictedFQN, Value: "restricted"},
			{Fqn: classPublicFQN, Value: "public"},
			// lowest in hierarchy
		},
	}

	// Setup project attribute (ALL_OF)
	s.allOfProjectAttr = &policy.Attribute{
		Fqn:  projectFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{Fqn: projectAvengersFQN, Value: "avengers"},
			{Fqn: projectJusticeLeagueFQN, Value: "justiceleague"},
			{Fqn: projectXmenFQN, Value: "xmen"},
			{Fqn: projectFantasicFourFQN, Value: "fantasticfour"},
		},
	}

	// Setup department attribute (ANY_OF)
	s.anyOfDepartmentAttr = &policy.Attribute{
		Fqn:  departmentFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{Fqn: deptFinanceFQN, Value: "finance"},
			{Fqn: deptMarketingFQN, Value: "marketing"},
		},
	}

	// Setup accessible attribute values map
	s.accessibleAttrValues = map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfidentialFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: classConfidentialFQN},
		},
		classSecretFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: classSecretFQN},
		},
		classRestrictedFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: classRestrictedFQN},
		},
		classTopSecretFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: classTopSecretFQN},
		},
		classPublicFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: classPublicFQN},
		},
		deptFinanceFQN: {
			Attribute: s.anyOfDepartmentAttr,
			Value:     &policy.Value{Fqn: deptFinanceFQN},
		},
		deptMarketingFQN: {
			Attribute: s.anyOfDepartmentAttr,
			Value:     &policy.Value{Fqn: deptMarketingFQN},
		},
		deptLegalFQN: {
			Attribute: s.anyOfDepartmentAttr,
			Value:     &policy.Value{Fqn: deptLegalFQN},
		},
		projectAvengersFQN: {
			Attribute: s.allOfProjectAttr,
			Value:     &policy.Value{Fqn: projectAvengersFQN},
		},
		projectJusticeLeagueFQN: {
			Attribute: s.allOfProjectAttr,
			Value:     &policy.Value{Fqn: projectJusticeLeagueFQN},
		},
		projectXmenFQN: {
			Attribute: s.allOfProjectAttr,
			Value:     &policy.Value{Fqn: projectXmenFQN},
		},
		projectFantasicFourFQN: {
			Attribute: s.allOfProjectAttr,
			Value:     &policy.Value{Fqn: projectFantasicFourFQN},
		},
	}
}

func TestEvaluateSuite(t *testing.T) {
	suite.Run(t, new(EvaluateTestSuite))
}

// Test cases for allOfRule
func (s *EvaluateTestSuite) TestAllOfRule() {
	tests := []struct {
		name              string
		resourceValueFQNs []string
		entitlements      subjectmappingbuiltin.AttributeValueFQNsToActions
		expectedFailures  int
	}{
		{
			name: "all entitlements present",
			resourceValueFQNs: []string{
				projectAvengersFQN,
				projectJusticeLeagueFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN:      []*policy.Action{actionRead},
				projectJusticeLeagueFQN: []*policy.Action{actionRead},
			},
			expectedFailures: 0,
		},
		{
			name: "one entitlement (action) missing",
			resourceValueFQNs: []string{
				projectJusticeLeagueFQN,
				projectFantasicFourFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectJusticeLeagueFQN: []*policy.Action{actionRead},
				projectFantasicFourFQN:  []*policy.Action{actionCreate}, // Wrong action
			},
			expectedFailures: 1,
		},
		{
			name: "all entitlement (actions) missing",
			resourceValueFQNs: []string{
				projectXmenFQN,
				projectJusticeLeagueFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectXmenFQN:          []*policy.Action{actionCreate}, // Wrong action
				projectJusticeLeagueFQN: []*policy.Action{actionCreate}, // Wrong action
			},
			expectedFailures: 2,
		},
		{
			name: "missing FQN in entitlements",
			resourceValueFQNs: []string{
				projectAvengersFQN,
				projectFantasicFourFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN: []*policy.Action{actionRead},
				// Missing classRestrictedFQN entirely
			},
			expectedFailures: 1,
		},
		{
			name: "multiple entitlements with mixed actions",
			resourceValueFQNs: []string{
				projectAvengersFQN,
				projectJusticeLeagueFQN,
				projectXmenFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN:      []*policy.Action{actionRead, actionCreate},
				projectJusticeLeagueFQN: []*policy.Action{actionRead},
				projectXmenFQN:          []*policy.Action{actionRead, actionCreate},
			},
			expectedFailures: 0, // All resources have read action entitled
		},
		{
			name:              "empty resource list",
			resourceValueFQNs: []string{},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN:      []*policy.Action{actionRead},
				projectJusticeLeagueFQN: []*policy.Action{actionRead},
			},
			expectedFailures: 0, // No resources to check, should pass
		},
		{
			name: "empty entitlements",
			resourceValueFQNs: []string{
				projectAvengersFQN,
				projectJusticeLeagueFQN,
			},
			entitlements:     subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectedFailures: 2, // All resources should fail
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			failures := allOfRule(s.T().Context(), s.logger, tc.entitlements, s.action, tc.resourceValueFQNs)

			s.Len(failures, tc.expectedFailures)

			// If expected failures, verify they are for the correct FQNs
			if tc.expectedFailures > 0 {
				failedFQNs := make(map[string]bool)
				for _, failure := range failures {
					failedFQNs[failure.AttributeValueFQN] = true
					s.Equal(s.action.GetName(), failure.ActionName)
				}

				// Verify each failure is for an actual resource value FQN
				for _, fqn := range tc.resourceValueFQNs {
					if entitlementActions, exists := tc.entitlements[fqn]; !exists {
						s.True(failedFQNs[fqn], "FQN %s should be in failures", fqn)
					} else {
						hasReadAction := false
						for _, entAction := range entitlementActions {
							if entAction.GetName() == s.action.GetName() {
								hasReadAction = true
								break
							}
						}
						if !hasReadAction {
							s.True(failedFQNs[fqn], "FQN %s should be in failures", fqn)
						}
					}
				}
			}
		})
	}
}

// Test cases for anyOfRule
func (s *EvaluateTestSuite) TestAnyOfRule() {
	tests := []struct {
		name              string
		resourceValueFQNs []string
		entitlements      subjectmappingbuiltin.AttributeValueFQNsToActions
		expectedFailCount int
	}{
		{
			name: "all entitlements present",
			resourceValueFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN:   []*policy.Action{actionRead},
				deptMarketingFQN: []*policy.Action{actionRead},
			},
			expectedFailCount: 0,
		},
		{
			name: "one entitlement present",
			resourceValueFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN:   []*policy.Action{actionRead},
				deptMarketingFQN: []*policy.Action{actionCreate}, // Wrong action
			},
			expectedFailCount: 0, // Still passes because at least one is entitled
		},
		{
			name: "no entitlements present",
			resourceValueFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN:   []*policy.Action{actionCreate}, // Wrong action
				deptMarketingFQN: []*policy.Action{actionCreate}, // Wrong action
			},
			expectedFailCount: 2, // Both failed so rule fails
		},
		{
			name: "no matching FQNs",
			resourceValueFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptLegalFQN: []*policy.Action{actionRead}, // Wrong FQN
			},
			expectedFailCount: 2, // Both failed so rule fails
		},
		{
			name: "entitlement with multiple actions",
			resourceValueFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN: []*policy.Action{actionCreate, actionRead}, // Has multiple actions including the required one
			},
			expectedFailCount: 0, // Should pass as at least one FQN has the required action
		},
		{
			name: "single resource with required entitlement",
			resourceValueFQNs: []string{
				deptFinanceFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN: []*policy.Action{actionRead},
			},
			expectedFailCount: 0,
		},
		{
			name:              "empty resource list",
			resourceValueFQNs: []string{},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN:   []*policy.Action{actionRead},
				deptMarketingFQN: []*policy.Action{actionRead},
			},
			expectedFailCount: 0, // Should pass as there are no resources to check
		},
		{
			name: "empty entitlements",
			resourceValueFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements:      subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectedFailCount: 2, // Should fail as there are no entitlements
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			// Execute
			failures := anyOfRule(s.T().Context(), s.logger, tc.entitlements, s.action, tc.resourceValueFQNs)

			// Assert
			if tc.expectedFailCount == 0 {
				s.Nil(failures, "Expected no failures but got: %v", failures)
			} else {
				s.Len(failures, tc.expectedFailCount)

				// Verify each failure is for an actual resource value FQN
				failedFQNs := make(map[string]bool)
				for _, failure := range failures {
					failedFQNs[failure.AttributeValueFQN] = true
					s.Equal(s.action.GetName(), failure.ActionName)
				}

				for _, fqn := range tc.resourceValueFQNs {
					// If this FQN has no entitlements or doesn't have the right action, it should be in failures
					hasRightEntitlement := false
					if entitlementActions, exists := tc.entitlements[fqn]; exists {
						for _, entAction := range entitlementActions {
							if entAction.GetName() == s.action.GetName() {
								hasRightEntitlement = true
								break
							}
						}
					}

					if !hasRightEntitlement {
						s.True(failedFQNs[fqn], "FQN %s should be in failures", fqn)
					}
				}
			}
		})
	}
}

// Test cases for hierarchyRule
func (s *EvaluateTestSuite) TestHierarchyRule() {
	tests := []struct {
		name              string
		resourceValueFQNs []string
		entitlements      subjectmappingbuiltin.AttributeValueFQNsToActions
		expectedFailures  bool
	}{
		{
			name: "entitled to highest value",
			resourceValueFQNs: []string{
				classSecretFQN,
				classConfidentialFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN: []*policy.Action{actionRead}, // Entitled to highest value
			},
			expectedFailures: false,
		},
		{
			name: "entitled to higher value",
			resourceValueFQNs: []string{
				classRestrictedFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classTopSecretFQN: []*policy.Action{actionRead}, // Entitled to highest value
			},
			expectedFailures: false,
		},
		{
			name: "entitled to higher value 2",
			resourceValueFQNs: []string{
				classRestrictedFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN: []*policy.Action{actionRead}, // Entitled to higher value
			},
			expectedFailures: false,
		},
		{
			name: "multi higher entitlements",
			resourceValueFQNs: []string{
				classPublicFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN:       []*policy.Action{actionRead}, // higher
				classConfidentialFQN: []*policy.Action{actionRead}, // higher
			},
			expectedFailures: false,
		},
		{
			name: "higher and lower entitlements",
			resourceValueFQNs: []string{
				classRestrictedFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classPublicFQN: []*policy.Action{actionRead}, // lower
				classSecretFQN: []*policy.Action{actionRead}, // higher
			},
			expectedFailures: false,
		},
		{
			name: "entitled to lower value but not highest",
			resourceValueFQNs: []string{
				classSecretFQN,
				classConfidentialFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classConfidentialFQN: []*policy.Action{actionRead}, // Only entitled to lower value
			},
			expectedFailures: true,
		},
		{
			name: "entitled to wrong action on highest value",
			resourceValueFQNs: []string{
				classSecretFQN,
				classConfidentialFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN: []*policy.Action{actionCreate}, // Wrong action
			},
			expectedFailures: true,
		},
		{
			name: "highest value from multiple resources",
			resourceValueFQNs: []string{
				classConfidentialFQN,
				classTopSecretFQN, // This is highest
				classRestrictedFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classTopSecretFQN: []*policy.Action{actionRead},
			},
			expectedFailures: false,
		},
		{
			name: "entitled to much higher value in hierarchy than requested",
			resourceValueFQNs: []string{
				classPublicFQN, // Lowest in hierarchy (index 4)
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classTopSecretFQN: []*policy.Action{actionRead}, // Highest in hierarchy (index 0)
			},
			expectedFailures: false, // Should pass with the fix
		},
		{
			name: "entitled to multiple values higher in hierarchy than requested",
			resourceValueFQNs: []string{
				classRestrictedFQN, // Lower in hierarchy (index 3)
				classPublicFQN,     // Lowest in hierarchy (index 4)
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				// No entitlement for exact matches
				classTopSecretFQN: []*policy.Action{actionRead}, // Much higher in hierarchy (index 0)
				classSecretFQN:    []*policy.Action{actionRead}, // Higher in hierarchy (index 1)
			},
			expectedFailures: false, // Should pass with the fix
		},
		{
			name: "entitled to value higher than highest requested but wrong action",
			resourceValueFQNs: []string{
				classConfidentialFQN, // Middle in hierarchy (index 2)
				classRestrictedFQN,   // Lower in hierarchy (index 3)
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN:    []*policy.Action{actionCreate}, // Higher but wrong action
				classTopSecretFQN: []*policy.Action{actionCreate}, // Highest but wrong action
			},
			expectedFailures: true, // Should fail due to wrong action
		},
		{
			name:              "empty resource list",
			resourceValueFQNs: []string{},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN: []*policy.Action{actionRead},
			},
			expectedFailures: false, // No resources to check, should pass
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			// Execute
			failures := hierarchyRule(s.T().Context(), s.logger, tc.entitlements, s.action, tc.resourceValueFQNs, s.hierarchicalClassAttr)

			// Assert
			if tc.expectedFailures {
				s.NotEmpty(failures, "Expected failures but got none")
			} else {
				s.Empty(failures, "Expected no failures but got: %v", failures)
			}
		})
	}
}

// Test cases for evaluateDefinition
func (s *EvaluateTestSuite) TestEvaluateDefinition() {
	tests := []struct {
		name           string
		definition     *policy.Attribute
		resourceValues []string
		entitlements   subjectmappingbuiltin.AttributeValueFQNsToActions
		expectPass     bool
		expectError    bool
	}{
		{
			name:       "all-of rule passing",
			definition: s.allOfProjectAttr,
			resourceValues: []string{
				classConfidentialFQN,
				classRestrictedFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classConfidentialFQN: []*policy.Action{actionRead},
				classRestrictedFQN:   []*policy.Action{actionRead},
			},
			expectPass:  true,
			expectError: false,
		},
		{
			name:       "any-of rule passing",
			definition: s.anyOfDepartmentAttr,
			resourceValues: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN: []*policy.Action{actionRead},
			},
			expectPass:  true,
			expectError: false,
		},
		{
			name:       "hierarchy rule passing",
			definition: s.hierarchicalClassAttr,
			resourceValues: []string{
				classSecretFQN,
				classConfidentialFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classSecretFQN: []*policy.Action{actionRead},
			},
			expectPass:  true,
			expectError: false,
		},
		{
			name: "unspecified rule type",
			definition: &policy.Attribute{
				Fqn:  classificationFQN,
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
				Values: []*policy.Value{
					{Fqn: classConfidentialFQN},
				},
			},
			resourceValues: []string{classConfidentialFQN},
			entitlements:   subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectPass:     false,
			expectError:    true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			result, err := evaluateDefinition(s.T().Context(), s.logger, tc.entitlements, s.action, tc.resourceValues, tc.definition)

			if tc.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
				s.NotNil(result)
				s.Equal(tc.expectPass, result.Passed)
			}
		})
	}
}

// Test cases for evaluateResourceAttributeValues
func (s *EvaluateTestSuite) TestEvaluateResourceAttributeValues() {
	tests := []struct {
		name             string
		resourceAttrs    *authz.Resource_AttributeValues
		entitlements     subjectmappingbuiltin.AttributeValueFQNsToActions
		expectAccessible bool
		expectError      bool
	}{
		{
			name: "all rules passing",
			resourceAttrs: &authz.Resource_AttributeValues{
				Fqns: []string{
					classConfidentialFQN,
					deptFinanceFQN,
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classConfidentialFQN: []*policy.Action{actionRead},
				deptFinanceFQN:       []*policy.Action{actionRead},
			},
			expectAccessible: true,
			expectError:      false,
		},
		{
			name: "one rule failing",
			resourceAttrs: &authz.Resource_AttributeValues{
				Fqns: []string{
					classConfidentialFQN,
					deptFinanceFQN,
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classConfidentialFQN: []*policy.Action{actionRead},
				deptFinanceFQN:       []*policy.Action{actionCreate}, // Wrong action
			},
			expectAccessible: false,
			expectError:      false,
		},
		{
			name: "unknown attribute value FQN",
			resourceAttrs: &authz.Resource_AttributeValues{
				Fqns: []string{
					classConfidentialFQN,
					"https://namespace.com/attr/department/value/unknown", // This FQN doesn't exist in accessibleAttributeValues
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classConfidentialFQN: []*policy.Action{actionRead},
			},
			expectAccessible: false,
			expectError:      true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			resourceDecision, err := evaluateResourceAttributeValues(
				s.T().Context(),
				s.logger,
				tc.resourceAttrs,
				"test-resource-id",
				s.action,
				tc.entitlements,
				s.accessibleAttrValues,
			)

			if tc.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
				s.NotNil(resourceDecision)
				s.Equal(tc.expectAccessible, resourceDecision.Passed)

				// Check results array has the correct length based on grouping by definition
				definitions := make(map[string]bool)
				for _, fqn := range tc.resourceAttrs.Fqns {
					if attrAndValue, ok := s.accessibleAttrValues[fqn]; ok {
						definitions[attrAndValue.Attribute.GetFqn()] = true
					}
				}
				s.Len(resourceDecision.DataRuleResults, len(definitions))
			}
		})
	}
}

// Test cases for getResourceDecision
func (s *EvaluateTestSuite) TestGetResourceDecision() {
	tests := []struct {
		name         string
		resource     *authz.Resource
		entitlements subjectmappingbuiltin.AttributeValueFQNsToActions
		expectError  bool
	}{
		{
			name: "attribute values resource",
			resource: &authz.Resource{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{classConfidentialFQN},
					},
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				classConfidentialFQN: []*policy.Action{actionRead},
			},
			expectError: false,
		},
		{
			name:         "invalid nil resource",
			resource:     nil,
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectError:  true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			decision, err := getResourceDecision(
				s.T().Context(),
				s.logger,
				s.accessibleAttrValues,
				tc.entitlements,
				s.action,
				tc.resource,
			)

			if tc.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
				s.NotNil(decision)
			}
		})
	}
}
