package access

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/actions"
)

// Constants for namespaces and attribute FQNs
var (
	// Base namespaces
	baseNamespace = "https://namespace.com"
	levelFQN      = createAttrFQN(baseNamespace, "level")
	departmentFQN = createAttrFQN(baseNamespace, "department")
	projectFQN    = createAttrFQN(baseNamespace, "project")

	// Leveled values
	levelHighestFQN  = createAttrValueFQN(baseNamespace, "level", "highest")
	levelUpperMidFQN = createAttrValueFQN(baseNamespace, "level", "upper_mid")
	levelMidFQN      = createAttrValueFQN(baseNamespace, "level", "mid")
	levelLowerMidFQN = createAttrValueFQN(baseNamespace, "level", "lower_mid")
	levelLowestFQN   = createAttrValueFQN(baseNamespace, "level", "lowest")

	// Department values
	deptFinanceFQN   = createAttrValueFQN(baseNamespace, "department", "finance")
	deptMarketingFQN = createAttrValueFQN(baseNamespace, "department", "marketing")
	deptLegalFQN     = createAttrValueFQN(baseNamespace, "department", "legal")

	// Project values
	projectJusticeLeagueFQN = createAttrValueFQN(baseNamespace, "project", "justiceleague")
	projectAvengersFQN      = createAttrValueFQN(baseNamespace, "project", "avengers")
	projectXmenFQN          = createAttrValueFQN(baseNamespace, "project", "xmen")
	projectFantasicFourFQN  = createAttrValueFQN(baseNamespace, "project", "fantasticfour")

	// Registered resource values
	netRegResValFQN  = createRegisteredResourceValueFQN("network", "external")
	platRegResValFQN = createRegisteredResourceValueFQN("platform", "internal")
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
	hierarchicalClassAttr              *policy.Attribute
	allOfProjectAttr                   *policy.Attribute
	anyOfDepartmentAttr                *policy.Attribute
	accessibleAttrValues               map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue
	accessibleRegisteredResourceValues map[string]*policy.RegisteredResourceValue
}

func (s *EvaluateTestSuite) SetupTest() {
	s.logger = logger.CreateTestLogger()
	s.action = actionRead

	// Setup classification attribute (HIERARCHY)
	s.hierarchicalClassAttr = &policy.Attribute{
		Fqn:  levelFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			// highest in hierarchy
			{Fqn: levelHighestFQN, Value: "highest"},
			{Fqn: levelUpperMidFQN, Value: "upper_mid"},
			{Fqn: levelMidFQN, Value: "mid"},
			{Fqn: levelLowerMidFQN, Value: "lower_mid"},
			{Fqn: levelLowestFQN, Value: "lowest"},
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
		levelMidFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: levelMidFQN},
		},
		levelUpperMidFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: levelUpperMidFQN},
		},
		levelLowerMidFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: levelLowerMidFQN},
		},
		levelHighestFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: levelHighestFQN},
		},
		levelLowestFQN: {
			Attribute: s.hierarchicalClassAttr,
			Value:     &policy.Value{Fqn: levelLowestFQN},
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

	// Setup accessible registered resource values map
	// Create the registered resource values with action attribute values
	s.accessibleRegisteredResourceValues = map[string]*policy.RegisteredResourceValue{
		netRegResValFQN: {
			Id:    "network-registered-res-id",
			Value: "external",
			ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
				{
					Id:     "network-action-attr-val-1",
					Action: actionRead,
					AttributeValue: &policy.Value{
						Fqn:   levelHighestFQN,
						Value: "highest",
					},
				},
				{
					Id:     "network-action-attr-val-2",
					Action: actionCreate,
					AttributeValue: &policy.Value{
						Fqn:   levelMidFQN,
						Value: "mid",
					},
				},
			},
		},
		platRegResValFQN: {
			Id:    "platform-registered-res-id",
			Value: "internal",
			ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
				{
					Id:     "platform-action-attr-val-1",
					Action: actionRead,
					AttributeValue: &policy.Value{
						Fqn:   projectAvengersFQN,
						Value: "avengers",
					},
				},
				{
					Id:     "platform-action-attr-val-2",
					Action: actionRead,
					AttributeValue: &policy.Value{
						Fqn:   projectJusticeLeagueFQN,
						Value: "justiceleague",
					},
				},
			},
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
				// Missing levelLowerMidFQN entirely
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
			if tc.expectedFailures == 0 {
				return
			}
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
						if strings.EqualFold(entAction.GetName(), s.action.GetName()) {
							hasReadAction = true
							break
						}
					}
					if !hasReadAction {
						s.True(failedFQNs[fqn], "FQN %s should be in failures", fqn)
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
				return
			}

			s.Len(failures, tc.expectedFailCount)

			// Verify each failure is for an actual resource value FQN
			failedFQNs := make(map[string]bool)
			for _, failure := range failures {
				failedFQNs[failure.AttributeValueFQN] = true
				s.Equal(s.action.GetName(), failure.ActionName)
			}

			for _, fqn := range tc.resourceValueFQNs {
				// If this FQN has no entitlements or doesn't have the right action, it should be in failures
				if entitlementActions, exists := tc.entitlements[fqn]; exists {
					hasRightEntitlement := false
					for _, entAction := range entitlementActions {
						if strings.EqualFold(entAction.GetName(), s.action.GetName()) {
							hasRightEntitlement = true
							break
						}
					}
					if hasRightEntitlement {
						continue
					}
				}
				s.True(failedFQNs[fqn], "FQN %s should be in failures", fqn)
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
				levelUpperMidFQN,
				levelMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionRead}, // Entitled to highest value
			},
			expectedFailures: false,
		},
		{
			name: "entitled to higher value",
			resourceValueFQNs: []string{
				levelLowerMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelHighestFQN: []*policy.Action{actionRead}, // Entitled to highest value
			},
			expectedFailures: false,
		},
		{
			name: "entitled to higher value 2",
			resourceValueFQNs: []string{
				levelLowerMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionRead}, // Entitled to higher value
			},
			expectedFailures: false,
		},
		{
			name: "multi higher entitlements",
			resourceValueFQNs: []string{
				levelLowestFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionRead}, // higher
				levelMidFQN:      []*policy.Action{actionRead}, // higher
			},
			expectedFailures: false,
		},
		{
			name: "higher and lower entitlements",
			resourceValueFQNs: []string{
				levelLowerMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelLowestFQN:   []*policy.Action{actionRead}, // lower
				levelUpperMidFQN: []*policy.Action{actionRead}, // higher
			},
			expectedFailures: false,
		},
		{
			name: "entitled to lower value but not highest",
			resourceValueFQNs: []string{
				levelUpperMidFQN,
				levelMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN: []*policy.Action{actionRead}, // Only entitled to lower value
			},
			expectedFailures: true,
		},
		{
			name: "entitled to wrong action on highest value",
			resourceValueFQNs: []string{
				levelUpperMidFQN,
				levelMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionCreate}, // Wrong action
			},
			expectedFailures: true,
		},
		{
			name: "highest value from multiple resources",
			resourceValueFQNs: []string{
				levelMidFQN,
				levelHighestFQN, // This is highest
				levelLowerMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelHighestFQN: []*policy.Action{actionRead},
			},
			expectedFailures: false,
		},
		{
			name: "entitled to much higher value in hierarchy than requested",
			resourceValueFQNs: []string{
				levelLowestFQN, // Lowest in hierarchy (index 4)
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelHighestFQN: []*policy.Action{actionRead}, // Highest in hierarchy (index 0)
			},
			expectedFailures: false, // Should pass with the fix
		},
		{
			name: "entitled to multiple values higher in hierarchy than requested",
			resourceValueFQNs: []string{
				levelLowerMidFQN, // Lower in hierarchy (index 3)
				levelLowestFQN,   // Lowest in hierarchy (index 4)
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				// No entitlement for exact matches
				levelHighestFQN:  []*policy.Action{actionRead}, // Much higher in hierarchy (index 0)
				levelUpperMidFQN: []*policy.Action{actionRead}, // Higher in hierarchy (index 1)
			},
			expectedFailures: false, // Should pass with the fix
		},
		{
			name: "entitled to value higher than highest requested but wrong action",
			resourceValueFQNs: []string{
				levelMidFQN,      // Middle in hierarchy (index 2)
				levelLowerMidFQN, // Lower in hierarchy (index 3)
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionCreate}, // Higher but wrong action
				levelHighestFQN:  []*policy.Action{actionCreate}, // Highest but wrong action
			},
			expectedFailures: true, // Should fail due to wrong action
		},
		{
			name:              "empty resource list",
			resourceValueFQNs: []string{},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionRead},
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
				levelMidFQN,
				levelLowerMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN:      []*policy.Action{actionRead},
				levelLowerMidFQN: []*policy.Action{actionRead},
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
				levelUpperMidFQN,
				levelMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelUpperMidFQN: []*policy.Action{actionRead},
			},
			expectPass:  true,
			expectError: false,
		},
		{
			name: "unspecified rule type",
			definition: &policy.Attribute{
				Fqn:  levelFQN,
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
				Values: []*policy.Value{
					{Fqn: levelMidFQN},
				},
			},
			resourceValues: []string{levelMidFQN},
			entitlements:   subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectPass:     false,
			expectError:    true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			result, err := evaluateDefinition(s.T().Context(), s.logger, tc.entitlements, s.action, tc.resourceValues, tc.definition, false)

			if tc.expectError {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.NotNil(result)
				s.Equal(tc.expectPass, result.Passed)
			}
		})
	}
}

func (s *EvaluateTestSuite) TestEvaluateDefinition_NamespacedPolicy() {
	namespaceA := &policy.Namespace{Id: "11111111-1111-1111-1111-111111111111", Fqn: "https://ns-a.example.com"}
	namespaceB := &policy.Namespace{Id: "22222222-2222-2222-2222-222222222222", Fqn: "https://ns-b.example.com"}

	allOfDef := &policy.Attribute{
		Id:        "all-of-def",
		Fqn:       projectFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Namespace: namespaceA,
		Values: []*policy.Value{
			{Fqn: projectAvengersFQN},
			{Fqn: projectJusticeLeagueFQN},
		},
	}

	anyOfDef := &policy.Attribute{
		Id:        "any-of-def",
		Fqn:       departmentFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Namespace: namespaceA,
		Values: []*policy.Value{
			{Fqn: deptFinanceFQN},
			{Fqn: deptMarketingFQN},
		},
	}

	hierarchyDef := &policy.Attribute{
		Id:        "hierarchy-def",
		Fqn:       levelFQN,
		Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Namespace: namespaceA,
		Values: []*policy.Value{
			{Fqn: levelHighestFQN},
			{Fqn: levelUpperMidFQN},
			{Fqn: levelMidFQN},
		},
	}

	tests := []struct {
		name          string
		definition    *policy.Attribute
		resourceFQNs  []string
		entitlements  subjectmappingbuiltin.AttributeValueFQNsToActions
		requested     *policy.Action
		namespaced    bool
		expectPass    bool
		expectErr     error
		errorContains string
	}{
		{
			name:       "all_of strict pass with matching namespace",
			definition: allOfDef,
			resourceFQNs: []string{
				projectAvengersFQN,
				projectJusticeLeagueFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN:      {{Name: actions.ActionNameRead, Namespace: namespaceA}},
				projectJusticeLeagueFQN: {{Name: actions.ActionNameRead, Namespace: namespaceA}},
			},
			requested:  &policy.Action{Name: actions.ActionNameRead},
			namespaced: true,
			expectPass: true,
		},
		{
			name:       "all_of strict fail with wrong namespace",
			definition: allOfDef,
			resourceFQNs: []string{
				projectAvengersFQN,
				projectJusticeLeagueFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN:      {{Name: actions.ActionNameRead, Namespace: namespaceB}},
				projectJusticeLeagueFQN: {{Name: actions.ActionNameRead, Namespace: namespaceB}},
			},
			requested:  &policy.Action{Name: actions.ActionNameRead},
			namespaced: true,
			expectPass: false,
		},
		{
			name:       "any_of strict pass when one namespace-matching action exists",
			definition: anyOfDef,
			resourceFQNs: []string{
				deptFinanceFQN,
				deptMarketingFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN:   {{Name: actions.ActionNameRead, Namespace: namespaceB}},
				deptMarketingFQN: {{Name: actions.ActionNameRead, Namespace: namespaceA}},
			},
			requested:  &policy.Action{Name: actions.ActionNameRead},
			namespaced: true,
			expectPass: true,
		},
		{
			name:       "hierarchy strict pass with higher entitled value in same namespace",
			definition: hierarchyDef,
			resourceFQNs: []string{
				levelUpperMidFQN,
				levelMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelHighestFQN: {{Name: actions.ActionNameRead, Namespace: namespaceA}},
			},
			requested:  &policy.Action{Name: actions.ActionNameRead},
			namespaced: true,
			expectPass: true,
		},
		{
			name:       "strict mode fails when definition namespace missing",
			definition: &policy.Attribute{Id: "def-no-ns", Fqn: levelFQN, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, Values: []*policy.Value{{Fqn: levelMidFQN}}},
			resourceFQNs: []string{
				levelMidFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN: {{Name: actions.ActionNameRead, Namespace: namespaceA}},
			},
			requested:  &policy.Action{Name: actions.ActionNameRead},
			namespaced: true,
			expectPass: false,
		},
		{
			name:       "request action namespace filter is enforced",
			definition: anyOfDef,
			resourceFQNs: []string{
				deptFinanceFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN: {{Name: actions.ActionNameRead, Namespace: namespaceA}},
			},
			requested:  &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceB},
			namespaced: false,
			expectPass: false,
		},
		{
			name:       "request action id precedence is enforced",
			definition: anyOfDef,
			resourceFQNs: []string{
				deptFinanceFQN,
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				deptFinanceFQN: {{Id: "entitled-id", Name: actions.ActionNameRead, Namespace: namespaceA}},
			},
			requested:  &policy.Action{Id: "requested-id", Name: actions.ActionNameRead},
			namespaced: true,
			expectPass: false,
		},
		{
			name:          "unspecified rule returns expected error",
			definition:    &policy.Attribute{Fqn: levelFQN, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED, Values: []*policy.Value{{Fqn: levelMidFQN}}},
			resourceFQNs:  []string{levelMidFQN},
			entitlements:  subjectmappingbuiltin.AttributeValueFQNsToActions{},
			requested:     &policy.Action{Name: actions.ActionNameRead},
			namespaced:    true,
			expectErr:     ErrMissingRequiredSpecifiedRule,
			errorContains: "cannot be unspecified",
		},
		{
			name:          "unknown rule returns expected error",
			definition:    &policy.Attribute{Fqn: levelFQN, Rule: policy.AttributeRuleTypeEnum(999)},
			resourceFQNs:  []string{levelMidFQN},
			entitlements:  subjectmappingbuiltin.AttributeValueFQNsToActions{},
			requested:     &policy.Action{Name: actions.ActionNameRead},
			namespaced:    true,
			expectErr:     ErrUnrecognizedRule,
			errorContains: "unrecognized",
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			result, err := evaluateDefinition(s.T().Context(), s.logger, tc.entitlements, tc.requested, tc.resourceFQNs, tc.definition, tc.namespaced)

			if tc.expectErr != nil {
				s.Require().Error(err)
				s.Require().ErrorIs(err, tc.expectErr)
				s.ErrorContains(err, tc.errorContains)
				return
			}

			s.Require().NoError(err)
			s.Require().NotNil(result)
			s.Equal(tc.expectPass, result.Passed)
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
					levelMidFQN,
					deptFinanceFQN,
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN:    []*policy.Action{actionRead},
				deptFinanceFQN: []*policy.Action{actionRead},
			},
			expectAccessible: true,
			expectError:      false,
		},
		{
			name: "one rule failing",
			resourceAttrs: &authz.Resource_AttributeValues{
				Fqns: []string{
					levelMidFQN,
					deptFinanceFQN,
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN:    []*policy.Action{actionRead},
				deptFinanceFQN: []*policy.Action{actionCreate}, // Wrong action
			},
			expectAccessible: false,
			expectError:      false,
		},
		{
			name: "partial FQNs not found - should DENY",
			resourceAttrs: &authz.Resource_AttributeValues{
				Fqns: []string{
					levelMidFQN,
					"https://namespace.com/attr/department/value/unknown",
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN: []*policy.Action{actionRead},
			},
			// Should NOT error - but should DENY resource (ANY missing FQN = DENY)
			expectAccessible: false,
			expectError:      false,
		},
		{
			name: "all FQNs not found - should DENY",
			resourceAttrs: &authz.Resource_AttributeValues{
				Fqns: []string{
					createAttrValueFQN(baseNamespace, "significance", "critical"),
					createAttrValueFQN(baseNamespace, "significance", "major"),
				},
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			// Should NOT error - but should DENY resource (no FQNs exist)
			expectAccessible: false,
			expectError:      false,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			notRegisteredResourceFQN := ""
			resourceDecision, err := evaluateResourceAttributeValues(
				s.T().Context(),
				s.logger,
				tc.resourceAttrs,
				"test-resource-id",
				notRegisteredResourceFQN,
				s.action,
				tc.entitlements,
				s.accessibleAttrValues,
				false,
			)

			if tc.expectError {
				s.Require().Error(err)
				return
			}

			s.Require().NoError(err)
			s.NotNil(resourceDecision)
			s.Equal(tc.expectAccessible, resourceDecision.Entitled)

			// Check results array has the correct length based on grouping by definition
			// If ANY FQN is missing, DataRuleResults should be empty (resource is denied without evaluation)
			definitions := make(map[string]bool)
			allFQNsExist := true
			for _, fqn := range tc.resourceAttrs.GetFqns() {
				if attrAndValue, ok := s.accessibleAttrValues[fqn]; ok {
					definitions[attrAndValue.GetAttribute().GetFqn()] = true
				} else {
					allFQNsExist = false
				}
			}

			if allFQNsExist {
				s.Len(resourceDecision.DataRuleResults, len(definitions))
			} else {
				// Any missing FQN means DENY without evaluation
				s.Empty(resourceDecision.DataRuleResults)
			}
		})
	}
}

// Test cases for getResourceDecision
func (s *EvaluateTestSuite) TestGetResourceDecision() {
	nonExistentRegResValueFQN := createRegisteredResourceValueFQN("nonexistent", "value")

	tests := []struct {
		name         string
		resource     *authz.Resource
		entitlements subjectmappingbuiltin.AttributeValueFQNsToActions
		expectError  bool
		expectPass   bool
	}{
		{
			name: "attribute values resource",
			resource: &authz.Resource{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{levelMidFQN},
					},
				},
				EphemeralId: "test-attr-values-id-1",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN: []*policy.Action{actionRead},
			},
			expectError: false,
			expectPass:  true,
		},
		{
			name: "registered resource value with all entitlements",
			resource: &authz.Resource{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: netRegResValFQN,
				},
				EphemeralId: "test-reg-res-id-1",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelHighestFQN: []*policy.Action{actionRead},
			},
			expectError: false,
			expectPass:  true,
		},
		{
			name: "registered resource value with project values",
			resource: &authz.Resource{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: platRegResValFQN,
				},
				EphemeralId: "test-reg-res-id-2",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				projectAvengersFQN:      []*policy.Action{actionRead},
				projectJusticeLeagueFQN: []*policy.Action{actionRead},
			},
			expectError: false,
			expectPass:  true,
		},
		{
			name: "registered resource value with missing entitlements",
			resource: &authz.Resource{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: platRegResValFQN,
				},
				EphemeralId: "test-reg-res-id-3",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				// Missing projectJusticeLeagueFQN
				projectAvengersFQN: []*policy.Action{actionRead},
			},
			expectError: false,
			expectPass:  false, // Missing entitlement for projectJusticeLeagueFQN
		},
		{
			name: "registered resource value with wrong action",
			resource: &authz.Resource{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: netRegResValFQN,
				},
				EphemeralId: "test-reg-res-id-4",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				// Wrong action
				levelHighestFQN: []*policy.Action{actionCreate},
			},
			expectError: false,
			expectPass:  false,
		},
		{
			name: "nonexistent registered resource value - should DENY",
			resource: &authz.Resource{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: nonExistentRegResValueFQN,
				},
				EphemeralId: "test-reg-res-id-5",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectError:  false,
			expectPass:   false,
		},
		{
			name: "attribute value FQNs not found, namespace & definition exist - should DENY",
			resource: &authz.Resource{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{
							createAttrValueFQN(baseNamespace, "department", "doesnotexist"),
						},
					},
				},
				EphemeralId: "test-attr-missing-fqns",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectError:  false,
			expectPass:   false,
		},
		{
			name: "attribute value FQNs not found, namespace exists - should DENY",
			resource: &authz.Resource{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{
							createAttrValueFQN(baseNamespace, "unknown", "doesnotexist"),
						},
					},
				},
				EphemeralId: "test-attr-missing-fqns",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectError:  false,
			expectPass:   false,
		},
		{
			name: "attribute value FQNs not found, namespace does not exist - should DENY",
			resource: &authz.Resource{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{
							"https://doesnot.exist/attr/severity/value/high",
						},
					},
				},
				EphemeralId: "test-attr-missing-fqns",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectError:  false,
			expectPass:   false,
		},
		{
			name: "attribute value FQNs partially exist - should DENY",
			resource: &authz.Resource{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{
							levelMidFQN,
							"https://doesnot.exist/attr/severity/value/high",
						},
					},
				},
				EphemeralId: "test-attr-values-partially-exist",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelMidFQN: []*policy.Action{actionRead},
			},
			expectError: false,
			expectPass:  false,
		},
		{
			name:         "invalid nil resource",
			resource:     nil,
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{},
			expectError:  true,
		},
		{
			name: "case insensitive registered resource value FQN",
			resource: &authz.Resource{
				Resource: &authz.Resource_RegisteredResourceValueFqn{
					RegisteredResourceValueFqn: strings.ToUpper(netRegResValFQN), // Test case insensitivity
				},
				EphemeralId: "test-reg-res-id-6",
			},
			entitlements: subjectmappingbuiltin.AttributeValueFQNsToActions{
				levelHighestFQN: []*policy.Action{actionRead},
			},
			expectError: false,
			expectPass:  true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			decision, err := getResourceDecision(
				s.T().Context(),
				s.logger,
				s.accessibleAttrValues,
				s.accessibleRegisteredResourceValues,
				tc.entitlements,
				s.action,
				tc.resource,
				false,
			)

			if tc.expectError {
				s.Require().Error(err)
			} else {
				s.Require().NoError(err)
				s.NotNil(decision)
				s.Equal(tc.expectPass, decision.Entitled, "Decision entitlement status didn't match")
				s.Equal(tc.resource.GetEphemeralId(), decision.ResourceID, "Resource ID didn't match")
			}
		})
	}
}

func (s *EvaluateTestSuite) Test_getResourceDecision_MultiResources_GranularDenials() {
	nonExistentFQN := createAttrValueFQN(baseNamespace, "space", "cosmic")

	// Resource 1: Valid FQN, entity is entitled
	resource1 := &authz.Resource{
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{
				Fqns: []string{levelHighestFQN},
			},
		},
		EphemeralId: "valid-resource-1",
	}

	// Resource 2: Non-existent FQN
	resource2 := &authz.Resource{
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{
				Fqns: []string{nonExistentFQN},
			},
		},
		EphemeralId: "invalid-resource-2",
	}

	// Resource 3: Valid FQN, entity is entitled
	resource3 := &authz.Resource{
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{
				Fqns: []string{levelMidFQN},
			},
		},
		EphemeralId: "valid-resource-3",
	}

	entitlements := subjectmappingbuiltin.AttributeValueFQNsToActions{
		levelHighestFQN: []*policy.Action{actionRead},
		levelMidFQN:     []*policy.Action{actionRead},
	}

	testCases := []struct {
		name             string
		resource         *authz.Resource
		expectedEntitled bool
	}{
		{"valid resource 1", resource1, true},
		{"invalid resource 2 (missing FQN)", resource2, false},
		{"valid resource 3", resource3, true},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			decision, err := getResourceDecision(
				s.T().Context(),
				s.logger,
				s.accessibleAttrValues,
				s.accessibleRegisteredResourceValues,
				entitlements,
				s.action,
				tc.resource,
				false,
			)

			s.Require().NoError(err, "Should not error for resource: %s", tc.name)
			s.Require().NotNil(decision)
			s.Equal(tc.expectedEntitled, decision.Entitled, "Entitlement mismatch for: %s", tc.name)
		})
	}
}

func (s *EvaluateTestSuite) Test_getResourceDecision_StrictMode_DeniesOnActionNamespaceMismatch() {
	namespaceA := &policy.Namespace{Id: "11111111-1111-1111-1111-111111111111", Fqn: "https://ns-a.example.com"}
	namespaceB := &policy.Namespace{Id: "22222222-2222-2222-2222-222222222222", Fqn: "https://ns-b.example.com"}

	s.accessibleAttrValues[projectAvengersFQN].Attribute.Namespace = namespaceA

	resource := &authz.Resource{
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{Fqns: []string{projectAvengersFQN}},
		},
		EphemeralId: "ns-mismatch-resource",
	}

	entitlements := subjectmappingbuiltin.AttributeValueFQNsToActions{
		projectAvengersFQN: {
			{Name: actions.ActionNameRead, Namespace: namespaceB},
		},
	}

	decision, err := getResourceDecision(
		s.T().Context(),
		s.logger,
		s.accessibleAttrValues,
		s.accessibleRegisteredResourceValues,
		entitlements,
		actionRead,
		resource,
		true,
	)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Entitled, "desired namespaced-policy behavior: same-name action in wrong namespace should deny")
}

func (s *EvaluateTestSuite) Test_getResourceDecision_StrictMode_RegisteredResourceFiltersAAVByNamespace() {
	namespaceA := &policy.Namespace{Id: "11111111-1111-1111-1111-111111111111", Fqn: "https://ns-a.example.com"}
	namespaceB := &policy.Namespace{Id: "22222222-2222-2222-2222-222222222222", Fqn: "https://ns-b.example.com"}

	s.accessibleAttrValues[levelHighestFQN].Attribute.Namespace = namespaceA
	s.accessibleRegisteredResourceValues[netRegResValFQN].ActionAttributeValues = []*policy.RegisteredResourceValue_ActionAttributeValue{
		{
			Id: "network-action-attr-val-wrong-ns",
			Action: &policy.Action{
				Name:      actions.ActionNameRead,
				Namespace: namespaceB,
			},
			AttributeValue: &policy.Value{Fqn: levelHighestFQN, Value: "highest"},
		},
	}

	resource := &authz.Resource{
		Resource:    &authz.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: netRegResValFQN},
		EphemeralId: "rr-ns-mismatch-resource",
	}

	entitlements := subjectmappingbuiltin.AttributeValueFQNsToActions{
		levelHighestFQN: {
			{Name: actions.ActionNameRead, Namespace: namespaceA},
		},
	}

	decision, err := getResourceDecision(
		s.T().Context(),
		s.logger,
		s.accessibleAttrValues,
		s.accessibleRegisteredResourceValues,
		entitlements,
		actionRead,
		resource,
		true,
	)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Entitled, "desired namespaced-policy behavior: RR AAV action namespace must match evaluated namespace")
}

func (s *EvaluateTestSuite) Test_getResourceDecision_RequestActionIDPrecedence() {
	namespaceA := &policy.Namespace{Id: "11111111-1111-1111-1111-111111111111", Fqn: "https://ns-a.example.com"}

	s.accessibleAttrValues[projectAvengersFQN].Attribute.Namespace = namespaceA

	resource := &authz.Resource{
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{Fqns: []string{projectAvengersFQN}},
		},
		EphemeralId: "request-action-id-precedence",
	}

	entitlements := subjectmappingbuiltin.AttributeValueFQNsToActions{
		projectAvengersFQN: {
			{Id: "entitled-id", Name: actions.ActionNameRead, Namespace: namespaceA},
		},
	}

	decision, err := getResourceDecision(
		s.T().Context(),
		s.logger,
		s.accessibleAttrValues,
		s.accessibleRegisteredResourceValues,
		entitlements,
		&policy.Action{Id: "different-id", Name: actions.ActionNameRead},
		resource,
		true,
	)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Entitled, "requested action id should take precedence over name match")
}

func (s *EvaluateTestSuite) Test_getResourceDecision_StrictMode_DeniesWhenAAVNamespaceCannotBeResolved() {
	namespaceA := &policy.Namespace{Id: "11111111-1111-1111-1111-111111111111", Fqn: "https://ns-a.example.com"}

	knownFQN := levelHighestFQN
	unknownFQN := "https://unknown.example.com/attr/missing/value/x"

	s.accessibleAttrValues[knownFQN].Attribute.Namespace = namespaceA
	s.accessibleRegisteredResourceValues[netRegResValFQN].ActionAttributeValues = []*policy.RegisteredResourceValue_ActionAttributeValue{
		{
			Id: "rr-aav-known",
			Action: &policy.Action{
				Name:      actions.ActionNameRead,
				Namespace: namespaceA,
			},
			AttributeValue: &policy.Value{Fqn: knownFQN, Value: "highest"},
		},
		{
			Id: "rr-aav-unknown",
			Action: &policy.Action{
				Name:      actions.ActionNameRead,
				Namespace: namespaceA,
			},
			AttributeValue: &policy.Value{Fqn: unknownFQN, Value: "x"},
		},
	}

	resource := &authz.Resource{
		Resource:    &authz.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: netRegResValFQN},
		EphemeralId: "rr-aav-unresolvable-ns",
	}

	entitlements := subjectmappingbuiltin.AttributeValueFQNsToActions{
		knownFQN: {
			{Name: actions.ActionNameRead, Namespace: namespaceA},
		},
	}

	decision, err := getResourceDecision(
		s.T().Context(),
		s.logger,
		s.accessibleAttrValues,
		s.accessibleRegisteredResourceValues,
		entitlements,
		actionRead,
		resource,
		true,
	)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Entitled, "strict mode should fail closed when any matching RR AAV namespace cannot be resolved")
}

func Test_isRequestedActionMatch(t *testing.T) {
	namespaceA := &policy.Namespace{Id: "11111111-1111-1111-1111-111111111111", Fqn: "https://ns-a.example.com"}
	namespaceB := &policy.Namespace{Id: "22222222-2222-2222-2222-222222222222", Fqn: "https://ns-b.example.com"}

	tests := []struct {
		name                string
		requestedAction     *policy.Action
		requiredNamespace   string
		entitledAction      *policy.Action
		namespacedPolicy    bool
		expectedActionMatch bool
	}{
		{
			name:                "nil requested action",
			requestedAction:     nil,
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceA},
			namespacedPolicy:    true,
			expectedActionMatch: false,
		},
		{
			name:                "id precedence denies same-name different-id",
			requestedAction:     &policy.Action{Id: "requested-id", Name: actions.ActionNameRead},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Id: "entitled-id", Name: actions.ActionNameRead, Namespace: namespaceA},
			namespacedPolicy:    true,
			expectedActionMatch: false,
		},
		{
			name:                "name is case-insensitive in legacy mode",
			requestedAction:     &policy.Action{Name: "READ"},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: "read"},
			namespacedPolicy:    false,
			expectedActionMatch: true,
		},
		{
			name:                "request namespace id must match entitled namespace id",
			requestedAction:     &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceA},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceB},
			namespacedPolicy:    false,
			expectedActionMatch: false,
		},
		{
			name:                "request namespace fqn must match entitled namespace fqn",
			requestedAction:     &policy.Action{Name: actions.ActionNameRead, Namespace: &policy.Namespace{Fqn: "https://ns-a.example.com"}},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: actions.ActionNameRead, Namespace: &policy.Namespace{Id: namespaceA.GetId(), Fqn: "HTTPS://NS-A.EXAMPLE.COM"}},
			namespacedPolicy:    false,
			expectedActionMatch: true,
		},
		{
			name:                "strict mode requires required namespace id",
			requestedAction:     &policy.Action{Name: actions.ActionNameRead},
			requiredNamespace:   "",
			entitledAction:      &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceA},
			namespacedPolicy:    true,
			expectedActionMatch: false,
		},
		{
			name:                "strict mode requires entitled action namespace id",
			requestedAction:     &policy.Action{Name: actions.ActionNameRead},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: actions.ActionNameRead},
			namespacedPolicy:    true,
			expectedActionMatch: false,
		},
		{
			name:                "strict mode allows matching namespace id",
			requestedAction:     &policy.Action{Name: actions.ActionNameRead},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceA},
			namespacedPolicy:    true,
			expectedActionMatch: true,
		},
		{
			name:                "strict mode denies mismatched namespace id",
			requestedAction:     &policy.Action{Name: actions.ActionNameRead},
			requiredNamespace:   namespaceA.GetId(),
			entitledAction:      &policy.Action{Name: actions.ActionNameRead, Namespace: namespaceB},
			namespacedPolicy:    true,
			expectedActionMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := isRequestedActionMatch(context.Background(), logger.CreateTestLogger(), tt.requestedAction, tt.requiredNamespace, tt.entitledAction, tt.namespacedPolicy)
			assert.Equal(t, tt.expectedActionMatch, matched)
		})
	}
}
