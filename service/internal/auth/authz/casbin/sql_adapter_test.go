package casbin

import (
	"testing"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "failed to create test database")
	return db
}

func TestSQLAdapter_CreateAndMigrate(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")
	require.NotNil(t, adapter, "adapter should not be nil")

	// Verify the table was created
	var count int64
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count casbin_rule table")
	assert.Equal(t, int64(0), count, "casbin_rule table should be empty")
}

func TestSQLAdapter_LoadPolicy(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")

	// Insert test rules directly
	rules := []CasbinRule{
		{Ptype: "p", V0: "role:admin", V1: "*", V2: "*", V3: "allow"},
		{Ptype: "p", V0: "role:user", V1: "/test", V2: "read", V3: "allow"},
		{Ptype: "g", V0: "alice", V1: "role:admin"},
	}
	err = db.Create(&rules).Error
	require.NoError(t, err, "failed to insert test rules")

	// Load policy
	m, err := casbinModel.NewModelFromString(modelV2)
	require.NoError(t, err, "failed to create model")

	err = adapter.LoadPolicy(m)
	require.NoError(t, err, "failed to load policy")

	// Verify rules were loaded
	assert.Len(t, m["p"]["p"].Policy, 2, "should have 2 p rules")
	assert.Len(t, m["g"]["g"].Policy, 1, "should have 1 g rule")
}

func TestSQLAdapter_SavePolicy(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")

	// Create a model with test policies
	m, err := casbinModel.NewModelFromString(modelV2)
	require.NoError(t, err, "failed to create model")

	// Add test policies to the model
	m["p"]["p"].Policy = [][]string{
		{"role:admin", "*", "*", "allow"},
		{"role:user", "/test", "read", "allow"},
	}
	m["g"]["g"].Policy = [][]string{
		{"alice", "role:admin"},
	}

	// Save policy
	err = adapter.SavePolicy(m)
	require.NoError(t, err, "failed to save policy")

	// Verify rules were saved
	var count int64
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(3), count, "should have 3 rules saved")

	// Verify specific rules
	var rules []CasbinRule
	err = db.Find(&rules).Error
	require.NoError(t, err, "failed to fetch rules")
	assert.Len(t, rules, 3, "should have 3 rules")
}

func TestSQLAdapter_AddAndRemovePolicy(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")

	// Add a policy
	err = adapter.AddPolicy("p", "p", []string{"role:test", "/api", "write", "allow"})
	require.NoError(t, err, "failed to add policy")

	// Verify it was added
	var count int64
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(1), count, "should have 1 rule")

	// Remove the policy
	err = adapter.RemovePolicy("p", "p", []string{"role:test", "/api", "write", "allow"})
	require.NoError(t, err, "failed to remove policy")

	// Verify it was removed
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(0), count, "should have 0 rules")
}

func TestSQLAdapter_RemoveFilteredPolicy(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")

	// Insert test rules
	rules := []CasbinRule{
		{Ptype: "p", V0: "role:admin", V1: "/api", V2: "read", V3: "allow"},
		{Ptype: "p", V0: "role:admin", V1: "/api", V2: "write", V3: "allow"},
		{Ptype: "p", V0: "role:user", V1: "/api", V2: "read", V3: "allow"},
	}
	err = db.Create(&rules).Error
	require.NoError(t, err, "failed to insert test rules")

	// Remove filtered policy - remove all role:admin policies
	err = adapter.RemoveFilteredPolicy("p", "p", 0, "role:admin")
	require.NoError(t, err, "failed to remove filtered policy")

	// Verify only role:user policy remains
	var count int64
	err = db.Model(&CasbinRule{}).Where("v0 = ?", "role:admin").Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(0), count, "should have 0 role:admin rules")

	err = db.Model(&CasbinRule{}).Where("v0 = ?", "role:user").Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(1), count, "should have 1 role:user rule")
}

func TestSeedPoliciesIfEmpty(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")

	// Test seeding when empty
	csvPolicy := `p, role:admin, *, *, allow
p, role:user, /test, read, allow
g, alice, role:admin`

	err = seedPoliciesIfEmpty(adapter, csvPolicy, log)
	require.NoError(t, err, "failed to seed policies")

	// Verify policies were seeded
	var count int64
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(3), count, "should have 3 rules seeded")

	// Test seeding when not empty (should skip)
	err = seedPoliciesIfEmpty(adapter, csvPolicy, log)
	require.NoError(t, err, "failed to seed policies second time")

	// Count should remain the same
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(3), count, "should still have 3 rules (not duplicated)")
}

func TestSQLAdapter_EnforcementParity(t *testing.T) {
	// Test that SQL adapter produces same enforcement results as CSV adapter
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	// Create SQL adapter and seed with default policy
	sqlAdapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")

	err = seedPoliciesIfEmpty(sqlAdapter, builtinPolicyV2, log)
	require.NoError(t, err, "failed to seed SQL adapter")

	// Create enforcer with SQL adapter
	m, err := casbinModel.NewModelFromString(modelV2)
	require.NoError(t, err, "failed to create model")

	sqlEnforcer, err := casbin.NewEnforcer(m, sqlAdapter)
	require.NoError(t, err, "failed to create SQL enforcer")

	err = sqlEnforcer.LoadPolicy()
	require.NoError(t, err, "failed to load policy from SQL adapter")

	// Register the dimension matching function
	sqlEnforcer.AddFunction("dimensionMatch", dimensionMatchFunc)

	// Create CSV enforcer for comparison
	csvCfg := authz.CasbinV2Config{
		BaseAdapterConfig: authz.BaseAdapterConfig{
			Logger: log,
		},
	}
	csvEnforcer, err := createV2EnforcerFromConfig(csvCfg, log)
	require.NoError(t, err, "failed to create CSV enforcer")

	// Test cases - both enforcers should produce identical results
	testCases := []struct {
		subject string
		rpc     string
		dims    string
		expect  bool
	}{
		{"role:admin", "/policy.attributes.AttributesService/GetAttribute", "", true},
		{"role:standard", "/policy.attributes.AttributesService/GetAttribute", "", true},
		{"role:unknown", "/policy.attributes.AttributesService/GetAttribute", "", false},
		{"role:admin", "/policy.attributes.AttributesService/CreateAttribute", "", true},
		{"role:standard", "/policy.attributes.AttributesService/CreateAttribute", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.subject+"_"+tc.rpc, func(t *testing.T) {
			sqlResult, err := sqlEnforcer.Enforce(tc.subject, tc.rpc, tc.dims)
			require.NoError(t, err, "SQL enforcer failed")

			csvResult, err := csvEnforcer.Enforce(tc.subject, tc.rpc, tc.dims)
			require.NoError(t, err, "CSV enforcer failed")

			assert.Equal(t, csvResult, sqlResult,
				"SQL and CSV enforcers should produce identical results for %s on %s",
				tc.subject, tc.rpc)
			assert.Equal(t, tc.expect, sqlResult,
				"Enforcement result should match expected for %s on %s",
				tc.subject, tc.rpc)
		})
	}
}

func TestSeedFromCSV_CommentsAndWhitespace(t *testing.T) {
	db := setupTestDB(t)
	log, _ := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})

	adapter, err := createSQLAdapter(db, "", log)
	require.NoError(t, err, "failed to create SQL adapter")
	sqlAdapter := adapter.(*sqlAdapter)

	// CSV with comments, whitespace, and various formatting
	csvPolicy := `# This is a comment
p, role:admin, *, *, allow

# Another comment
p, role:user  ,  /test  ,  read  ,  allow
g, alice, role:admin
`

	err = seedFromCSV(sqlAdapter, csvPolicy)
	require.NoError(t, err, "failed to seed from CSV")

	// Verify only actual rules were inserted (comments ignored)
	var count int64
	err = db.Model(&CasbinRule{}).Count(&count).Error
	require.NoError(t, err, "failed to count rules")
	assert.Equal(t, int64(3), count, "should have 3 rules (comments ignored)")

	// Verify whitespace was properly trimmed
	var rule CasbinRule
	err = db.Model(&CasbinRule{}).Where("ptype = ? AND v0 = ?", "p", "role:user").First(&rule).Error
	require.NoError(t, err, "failed to find role:user rule")
	assert.Equal(t, "/test", rule.V1, "V1 should have whitespace trimmed")
	assert.Equal(t, "read", rule.V2, "V2 should have whitespace trimmed")
}
