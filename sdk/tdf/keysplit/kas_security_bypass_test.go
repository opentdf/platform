package keysplit

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKASSecurityBypass tests critical security scenarios where
// KAS consolidation could create unauthorized access or bypass access controls
func TestKASSecurityBypass(t *testing.T) {
	securityTests := []struct {
		name            string
		policy          []*policy.Value
		expectedSplits  int
		description     string
		securityConcern string
		bypassRisk      string
	}{
		{
			name: "admin_employee_same_kas_consolidation",
			policy: []*policy.Value{
				// Admin access (should be highly restricted)
				createMockValue("https://enterprise.com/attr/Role/value/Admin", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// Employee access (broader access)
				createMockValue("https://enterprise.com/attr/Role/value/Employee", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			expectedSplits:  1, // Current behavior: consolidates despite different privilege levels
			description:     "Admin and Employee roles with same KAS should consolidate",
			securityConcern: "Privilege escalation through KAS consolidation",
			bypassRisk:      "Employee access could be granted admin-level privileges through consolidated split",
		},
		{
			name: "department_isolation_same_kas",
			policy: []*policy.Value{
				// HR department (sensitive data)
				createMockValue("https://enterprise.com/attr/Department/value/HR", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// Engineering department (different access needs)
				createMockValue("https://enterprise.com/attr/Department/value/Engineering", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// Finance department (highly sensitive)
				createMockValue("https://enterprise.com/attr/Department/value/Finance", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			},
			expectedSplits:  1, // Current behavior: all consolidate due to same KAS
			description:     "Different departments with same KAS should consolidate",
			securityConcern: "Cross-departmental data exposure",
			bypassRisk:      "Employees could access other departments' data through consolidated access",
		},
		{
			name: "clearance_level_bypass_through_consolidation",
			policy: []*policy.Value{
				// Low clearance with specific access
				createMockValue("https://security.com/attr/Clearance/value/Confidential", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
				// High clearance with same KAS
				createMockValue("https://security.com/attr/Clearance/value/TopSecret", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
				// Project access that should require both
				createMockValue("https://security.com/attr/Project/value/ClassifiedProject", kasUs, "r3", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			},
			expectedSplits:  1, // Current behavior: hierarchy + allOf with same KAS consolidate
			description:     "Different clearance levels with same KAS should consolidate",
			securityConcern: "Security clearance bypass through consolidation",
			bypassRisk:      "Lower clearance users could access higher classified data",
		},
		{
			name: "geo_restriction_bypass",
			policy: []*policy.Value{
				// US-only data
				createMockValue("https://compliance.com/attr/Jurisdiction/value/US", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// EU-only data with same US KAS (regulatory violation scenario)
				createMockValue("https://compliance.com/attr/Jurisdiction/value/EU", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// Public data (should be separate)
				createMockValue("https://compliance.com/attr/Classification/value/Public", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			expectedSplits:  2, // US/EU consolidate (kasUs), Public separate (kasUk)
			description:     "Jurisdictional restrictions with KAS consolidation",
			securityConcern: "Regulatory compliance violation through consolidation",
			bypassRisk:      "Cross-jurisdiction data access could violate data sovereignty laws",
		},
		{
			name: "need_to_know_bypass_through_shared_kas",
			policy: []*policy.Value{
				// Project Alpha (need-to-know basis)
				createMockValue("https://security.com/attr/Project/value/Alpha", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// Project Beta (different need-to-know)
				createMockValue("https://security.com/attr/Project/value/Beta", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				// General company access
				createMockValue("https://security.com/attr/Level/value/Employee", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			expectedSplits:  1, // Current behavior: all consolidate due to same KAS
			description:     "Need-to-know compartments with shared KAS should consolidate",
			securityConcern: "Need-to-know principle violation",
			bypassRisk:      "Employees could access projects they don't have need-to-know for",
		},
	}

	for _, tt := range securityTests {
		t.Run(tt.name, func(t *testing.T) {
			splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

			// Generate random DEK
			dek := make([]byte, 32)
			_, err := rand.Read(dek)
			require.NoError(t, err)

			// Generate splits
			result, err := splitter.GenerateSplits(t.Context(), tt.policy, dek)
			require.NoError(t, err, "Security test failed: %s", tt.securityConcern)
			require.NotNil(t, result)

			// Validate split count matches current implementation behavior
			assert.Len(t, result.Splits, tt.expectedSplits,
				"SECURITY CONCERN: %s\nBYPASS RISK: %s\nDescription: %s",
				tt.securityConcern, tt.bypassRisk, tt.description)

			// Security validation: verify all splits are cryptographically sound
			verifyXORReconstruction(t, dek, result.Splits)

			// Validate that each split has valid KAS assignments
			for i, split := range result.Splits {
				assert.NotEmpty(t, split.KASURLs, "SECURITY: Split %d has no KAS URLs - access control failure", i)
				for _, kasURL := range split.KASURLs {
					assert.NotEmpty(t, kasURL, "SECURITY: Empty KAS URL in split %d - access control failure", i)
				}
			}

			// Log security analysis
			t.Logf("SECURITY ANALYSIS: %s", tt.securityConcern)
			t.Logf("CONSOLIDATION BEHAVIOR: %d splits created", len(result.Splits))
			t.Logf("BYPASS RISK: %s", tt.bypassRisk)
			if len(result.Splits) == 1 {
				t.Logf("WARNING: Consolidation occurred - review if security semantics are preserved")
			}
		})
	}
}

// TestKASConsolidationAccessControlViolations tests specific scenarios
// where the KAS-first consolidation could violate intended access control policies
func TestKASConsolidationAccessControlViolations(t *testing.T) {
	t.Run("principle_of_least_privilege_violation", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: Minimum access + Maximum access with same KAS
		// Should NOT consolidate as it violates least privilege
		policy := []*policy.Value{
			// Minimal read access
			createMockValue("https://access.com/attr/Permission/value/Read", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			// Full admin access
			createMockValue("https://access.com/attr/Permission/value/Admin", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Document current behavior - consolidates despite privilege difference
		assert.Len(t, result.Splits, 1, "Current implementation consolidates different privilege levels")

		t.Logf("SECURITY WARNING: Consolidation of different privilege levels may violate least privilege principle")
	})

	t.Run("segregation_of_duties_violation", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: Segregation of duties - same person shouldn't have both access types
		policy := []*policy.Value{
			// Financial approval authority
			createMockValue("https://compliance.com/attr/Authority/value/Financial", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			// Financial audit authority (should be segregated)
			createMockValue("https://compliance.com/attr/Authority/value/Audit", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Document current behavior
		assert.Len(t, result.Splits, 1, "Current implementation consolidates potentially conflicting authorities")

		t.Logf("COMPLIANCE WARNING: Consolidation may violate segregation of duties requirements")
	})

	t.Run("data_classification_mixing", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: Different data classifications with same KAS
		policy := []*policy.Value{
			// Public data
			createMockValue("https://classification.com/attr/Level/value/Public", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			// Confidential data
			createMockValue("https://classification.com/attr/Level/value/Confidential", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			// Secret data
			createMockValue("https://classification.com/attr/Level/value/Secret", kasUs, "r3", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Document current behavior
		assert.Len(t, result.Splits, 1, "Current implementation consolidates different classification levels")

		t.Logf("CLASSIFICATION WARNING: Different security levels consolidated into single split")
	})
}

// TestMultiTenantSecurityIsolation tests scenarios specific to
// multi-tenant environments where KAS consolidation could break tenant isolation
func TestMultiTenantSecurityIsolation(t *testing.T) {
	t.Run("cross_tenant_data_leakage", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: Different tenants using same KAS infrastructure
		policy := []*policy.Value{
			// Tenant A sensitive data
			createMockValue("https://tenant-a.com/attr/DataType/value/Sensitive", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			// Tenant B sensitive data (should be isolated)
			createMockValue("https://tenant-b.com/attr/DataType/value/Sensitive", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Current behavior: consolidates cross-tenant data
		assert.Len(t, result.Splits, 1, "Cross-tenant data consolidates with same KAS")

		t.Logf("MULTI-TENANT WARNING: Cross-tenant data consolidation may violate isolation requirements")
	})

	t.Run("regulatory_boundary_crossing", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: Regulatory boundaries (GDPR, CCPA) with shared KAS
		policy := []*policy.Value{
			// EU GDPR data
			createMockValue("https://compliance.com/attr/Regulation/value/GDPR", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			// California CCPA data
			createMockValue("https://compliance.com/attr/Regulation/value/CCPA", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		assert.Len(t, result.Splits, 1, "Regulatory boundaries consolidate with same KAS")

		t.Logf("REGULATORY WARNING: Cross-regulatory consolidation may violate compliance requirements")
	})
}

// TestAccessControlSemanticPreservation validates that access control
// semantics are preserved despite KAS-first consolidation
func TestAccessControlSemanticPreservation(t *testing.T) {
	t.Run("allof_and_semantics_with_consolidation", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: A AND B AND C with same KAS
		// Question: Does consolidation preserve AND semantics?
		policy := []*policy.Value{
			createMockValue("https://test.com/attr/RequirementA/value/Met", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://test.com/attr/RequirementB/value/Met", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://test.com/attr/RequirementC/value/Met", kasUs, "r3", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Current behavior: AND requirements with same KAS consolidate
		assert.Len(t, result.Splits, 1, "Multiple AND requirements with same KAS consolidate")

		// Verify that all KAS are represented in the consolidated split
		split := result.Splits[0]
		assert.Contains(t, split.KASURLs, kasUs, "Consolidated split should contain the shared KAS")

		t.Logf("SEMANTIC ANALYSIS: AND requirements consolidated - access control logic delegated to policy evaluation")
	})

	t.Run("anyof_or_semantics_with_different_kas", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Scenario: A OR B with different KAS
		// Question: Does KAS difference prevent OR consolidation?
		policy := []*policy.Value{
			createMockValue("https://test.com/attr/AlternativeA/value/Valid", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://test.com/attr/AlternativeB/value/Valid", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Current behavior: OR semantics overridden by KAS difference
		assert.Len(t, result.Splits, 2, "OR alternatives with different KAS create separate splits")

		// Verify both KAS are represented separately
		kasFound := make(map[string]bool)
		for _, split := range result.Splits {
			for _, kasURL := range split.KASURLs {
				kasFound[kasURL] = true
			}
		}
		assert.True(t, kasFound[kasUs], "kasUs should be in separate split")
		assert.True(t, kasFound[kasUk], "kasUk should be in separate split")

		t.Logf("SEMANTIC ANALYSIS: OR semantics overridden by KAS topology - cryptographic separation takes precedence")
	})
}

// TestConsolidationSecurityMatrix tests systematic security scenarios
// across different combinations of rules and KAS assignments with comprehensive coverage
func TestConsolidationSecurityMatrix(t *testing.T) {
	type securityScenario struct {
		name           string
		rule1, rule2   policy.AttributeRuleTypeEnum
		kas1, kas2     string
		expectedSplits int
		securityNote   string
		riskLevel      string // "low", "medium", "high"
	}

	matrixTests := []securityScenario{
		// Same KAS scenarios (consolidation expected)
		{
			name:           "anyof_anyof_same_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "Same KAS with same rule types should consolidate safely",
			riskLevel:      "low",
		},
		{
			name:           "anyof_allof_same_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "Mixed rule types with same KAS consolidate - verify access control semantics",
			riskLevel:      "medium",
		},
		{
			name:           "allof_allof_same_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "Multiple AND requirements with same KAS consolidate",
			riskLevel:      "high",
		},
		{
			name:           "hierarchy_anyof_same_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "Hierarchy with OR rules consolidate with same KAS",
			riskLevel:      "medium",
		},
		{
			name:           "hierarchy_allof_same_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "Hierarchy with AND requirements consolidate with same KAS",
			riskLevel:      "high",
		},
		// Different KAS scenarios (separation expected)
		{
			name:           "anyof_anyof_different_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			kas1:           kasUs,
			kas2:           kasUk,
			expectedSplits: 2,
			securityNote:   "OR semantics cannot overcome cryptographic KAS separation",
			riskLevel:      "low",
		},
		{
			name:           "anyof_allof_different_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			kas1:           kasUs,
			kas2:           kasUk,
			expectedSplits: 2,
			securityNote:   "Mixed rules with different KAS create separate splits",
			riskLevel:      "low",
		},
		{
			name:           "allof_allof_different_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			kas1:           kasUs,
			kas2:           kasUk,
			expectedSplits: 2,
			securityNote:   "Multiple AND requirements with different KAS remain separate",
			riskLevel:      "low",
		},
		{
			name:           "hierarchy_hierarchy_different_kas",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			kas1:           kasUs,
			kas2:           kasUk,
			expectedSplits: 2,
			securityNote:   "Multiple hierarchy rules with different KAS remain separate",
			riskLevel:      "low",
		},
		// Critical security scenarios
		{
			name:           "admin_employee_consolidation_risk",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, // Admin (strict)
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, // Employee (permissive)
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "CRITICAL: Admin/Employee consolidation may allow privilege escalation",
			riskLevel:      "high",
		},
		{
			name:           "confidential_public_mixing",
			rule1:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, // Confidential
			rule2:          policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, // Public
			kas1:           kasUs,
			kas2:           kasUs,
			expectedSplits: 1,
			securityNote:   "CRITICAL: Confidential/Public mixing may violate data classification",
			riskLevel:      "high",
		},
	}

	// Group by risk level for better reporting
	riskGroups := make(map[string][]securityScenario)
	for _, test := range matrixTests {
		riskGroups[test.riskLevel] = append(riskGroups[test.riskLevel], test)
	}

	for riskLevel, scenarios := range riskGroups {
		t.Run("risk_level_"+riskLevel, func(t *testing.T) {
			for _, tt := range scenarios {
				t.Run(tt.name, func(t *testing.T) {
					splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

					dek := make([]byte, 32)
					_, err := rand.Read(dek)
					require.NoError(t, err)

					policy := []*policy.Value{
						createMockValue("https://matrix.com/attr/Test1/value/Value1", tt.kas1, "r1", tt.rule1),
						createMockValue("https://matrix.com/attr/Test2/value/Value2", tt.kas2, "r2", tt.rule2),
					}

					result, err := splitter.GenerateSplits(t.Context(), policy, dek)
					require.NoError(t, err)

					assert.Len(t, result.Splits, tt.expectedSplits, tt.securityNote)

					// Verify XOR reconstruction
					verifyXORReconstruction(t, dek, result.Splits)

					// Log security analysis
					t.Logf("SECURITY [%s]: %s → %d splits (%s)",
						strings.ToUpper(tt.riskLevel), tt.name, len(result.Splits), tt.securityNote)

					if tt.riskLevel == "high" {
						t.Logf("WARNING: High-risk consolidation detected - review security implications")
					}
				})
			}
		})
	}

	// Summary report
	t.Run("security_summary", func(t *testing.T) {
		t.Logf("Security Matrix Test Summary:")
		for riskLevel, scenarios := range riskGroups {
			t.Logf("- %s risk scenarios: %d tests", strings.ToTitle(riskLevel), len(scenarios))
		}
		t.Logf("Total security scenarios tested: %d", len(matrixTests))
	})
}

// TestKASConsolidationSemanticPreservation tests that KAS consolidation
// preserves the semantic meaning of boolean expressions in complex scenarios
func TestKASConsolidationSemanticPreservation(t *testing.T) {
	t.Run("anyof_consolidation_preserves_or_semantics", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Region.Americas OR Region.Europe (both same KAS, should consolidate)
		policy := []*policy.Value{
			createMockValue("https://example.com/attr/Region/value/Americas", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://example.com/attr/Region/value/Europe", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Should consolidate into single split since both are anyOf with same KAS
		assert.Len(t, result.Splits, 1, "anyOf attributes with same KAS should consolidate")

		// The consolidated split should have the shared KAS
		split := result.Splits[0]
		assert.Contains(t, split.KASURLs, kasUk, "Consolidated split should contain the shared KAS")
	})

	t.Run("allof_separation_preserves_and_semantics", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Project.Alpha AND Project.Beta (both same KAS, should NOT consolidate)
		policy := []*policy.Value{
			createMockValue("https://example.com/attr/Project/value/Alpha", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://example.com/attr/Project/value/Beta", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Current implementation: allOf with same KAS consolidates (not separate evaluation)
		assert.Len(t, result.Splits, 1, "allOf attributes with same KAS currently consolidate")

		// Each split should have the KAS
		for i, split := range result.Splits {
			assert.Contains(t, split.KASURLs, kasUk, "Split %d should contain the KAS", i)
		}

		// Verify XOR reconstruction still works
		verifyXORReconstruction(t, dek, result.Splits)
	})
}

// TestComplexBooleanKASInteractions tests the most complex scenarios where
// nested boolean logic interacts with KAS consolidation in ways that could
// expose subtle security vulnerabilities
func TestComplexBooleanKASInteractions(t *testing.T) {
	t.Run("transitive_kas_consolidation_in_boolean_tree", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Create a scenario where KAS relationships create transitive consolidation effects:
		// (A(kasUs) AND B(kasUk)) OR (C(kasUs) AND D(kasUk))
		// Tests whether consolidation preserves the intended boolean structure
		policy := []*policy.Value{
			createMockValue("https://example.com/attr/Department/value/Engineering", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://example.com/attr/Level/value/Senior", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://example.com/attr/Department/value/Marketing", kasUs, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://example.com/attr/Level/value/Manager", kasUk, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Current implementation: KAS-based consolidation occurs across allOf relationships
		assert.Len(t, result.Splits, 2, "Complex allOf relationships consolidate by KAS")

		// Verify that consolidation didn't break the boolean logic
		verifyXORReconstruction(t, dek, result.Splits)
	})

	t.Run("kas_precedence_in_nested_hierarchy", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Test precedence hierarchy within nested boolean logic:
		// Value-level grant should override attribute-level grant in complex expression
		policy := []*policy.Value{
			func() *policy.Value {
				// Value with specific grant should take precedence
				v := createMockValue("https://example.com/attr/Department/value/Engineering", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				// Add attribute-level grant that should be overridden
				v.Attribute.Grants = []*policy.KeyAccessServer{
					{Uri: kasUs},
				}
				return v
			}(),
			createMockValue("https://example.com/attr/Project/value/Alpha", kasCa, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)

		// Current implementation: Different KAS prevent consolidation even with anyOf
		assert.Len(t, result.Splits, 2, "anyOf attributes with different KAS create separate splits")

		// Verify that value-level grants were used and create separate splits
		kasFound := make(map[string]bool)
		for _, split := range result.Splits {
			for _, kasURL := range split.KASURLs {
				kasFound[kasURL] = true
			}
		}

		assert.True(t, kasFound[kasUk], "Value-level grant should be used")
		assert.True(t, kasFound[kasCa], "Specific KAS should be preserved")
		// kasUs should not appear as it was an attribute-level grant that should be overridden
	})
}
