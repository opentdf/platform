package casbin

import (
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	"github.com/glebarez/sqlite"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type SQLAdapterSuite struct {
	suite.Suite
	logger  *logger.Logger
	tempDir string
}

func TestSQLAdapterSuite(t *testing.T) {
	suite.Run(t, new(SQLAdapterSuite))
}

func (s *SQLAdapterSuite) SetupTest() {
	s.logger = logger.CreateTestLogger()
	// Create temp dir for test databases
	tempDir, err := os.MkdirTemp("", "casbin-test-*")
	s.Require().NoError(err)
	s.tempDir = tempDir
}

func (s *SQLAdapterSuite) TearDownTest() {
	// Clean up temp dir
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

// casbinRuleForTest is the table structure for Casbin policies (for test migrations).
type casbinRuleForTest struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:100"`
	V0    string `gorm:"size:100"`
	V1    string `gorm:"size:100"`
	V2    string `gorm:"size:100"`
	V3    string `gorm:"size:100"`
	V4    string `gorm:"size:100"`
	V5    string `gorm:"size:100"`
}

func (casbinRuleForTest) TableName() string {
	return "casbin_rule"
}

func (s *SQLAdapterSuite) TestCreateSQLAdapter_Success() {
	gormDB := s.createTestGormDB()

	adapter, err := CreateSQLAdapter(gormDB, "", s.logger)
	s.Require().NoError(err)
	s.Require().NotNil(adapter)
}

func (s *SQLAdapterSuite) TestCreateSQLAdapter_NilDB() {
	adapter, err := CreateSQLAdapter(nil, "", s.logger)
	s.Require().Error(err)
	s.Nil(adapter)
	s.Contains(err.Error(), "gormDB is required")
}

func (s *SQLAdapterSuite) TestSeedPoliciesIfEmpty_SeedsWhenEmpty() {
	gormDB := s.createTestGormDB()

	// Use CreateSQLAdapter which handles AutoMigrate properly
	adapter, err := CreateSQLAdapter(gormDB, "", s.logger)
	s.Require().NoError(err)

	m, err := casbinModel.NewModelFromString(modelV2)
	s.Require().NoError(err)

	enforcer, err := casbin.NewEnforcer(m, adapter)
	s.Require().NoError(err)

	// Verify store is empty
	policies, _ := enforcer.GetPolicy()
	s.Empty(policies)

	// Seed with test policies
	csvPolicy := `p, role:admin, *, *, allow
p, role:standard, /test/*, *, allow
g, testgroup, role:admin`

	err = SeedPoliciesIfEmpty(enforcer, csvPolicy, s.logger)
	s.Require().NoError(err)

	// Verify policies were seeded
	policies, _ = enforcer.GetPolicy()
	s.Len(policies, 2)

	groupings, _ := enforcer.GetGroupingPolicy()
	s.Len(groupings, 1)
}

func (s *SQLAdapterSuite) TestSeedPoliciesIfEmpty_SkipsWhenNotEmpty() {
	gormDB := s.createTestGormDB()

	// Use CreateSQLAdapter which handles AutoMigrate properly
	adapter, err := CreateSQLAdapter(gormDB, "", s.logger)
	s.Require().NoError(err)

	m, err := casbinModel.NewModelFromString(modelV2)
	s.Require().NoError(err)

	enforcer, err := casbin.NewEnforcer(m, adapter)
	s.Require().NoError(err)

	// Pre-populate with a policy
	_, err = enforcer.AddPolicy("role:existing", "/existing/*", "*", "allow")
	s.Require().NoError(err)
	err = enforcer.SavePolicy()
	s.Require().NoError(err)

	// Try to seed - should skip
	csvPolicy := `p, role:admin, *, *, allow
p, role:standard, /test/*, *, allow`

	err = SeedPoliciesIfEmpty(enforcer, csvPolicy, s.logger)
	s.Require().NoError(err)

	// Verify only the original policy exists
	policies, _ := enforcer.GetPolicy()
	s.Len(policies, 1)
	s.Equal([]string{"role:existing", "/existing/*", "*", "allow"}, policies[0])
}

func (s *SQLAdapterSuite) TestSeedPoliciesIfEmpty_Idempotent() {
	gormDB := s.createTestGormDB()

	// Use CreateSQLAdapter which handles AutoMigrate properly
	adapter, err := CreateSQLAdapter(gormDB, "", s.logger)
	s.Require().NoError(err)

	m, err := casbinModel.NewModelFromString(modelV2)
	s.Require().NoError(err)

	enforcer, err := casbin.NewEnforcer(m, adapter)
	s.Require().NoError(err)

	csvPolicy := `p, role:admin, *, *, allow`

	// First seed
	err = SeedPoliciesIfEmpty(enforcer, csvPolicy, s.logger)
	s.Require().NoError(err)

	// Second seed (should be no-op)
	err = SeedPoliciesIfEmpty(enforcer, csvPolicy, s.logger)
	s.Require().NoError(err)

	// Verify only one policy exists (not duplicated)
	policies, _ := enforcer.GetPolicy()
	s.Len(policies, 1)
}

func (s *SQLAdapterSuite) TestParsePolicyCSV() {
	csv := `# Comment line
p, role:admin, *, *, allow
p, role:standard, /test/*, *, allow

g, testgroup, role:admin
g, othergroup, role:standard
`

	policies, groupings := parsePolicyCSV(csv)

	s.Len(policies, 2)
	s.Equal([]string{"role:admin", "*", "*", "allow"}, policies[0])
	s.Equal([]string{"role:standard", "/test/*", "*", "allow"}, policies[1])

	s.Len(groupings, 2)
	s.Equal([]string{"testgroup", "role:admin"}, groupings[0])
	s.Equal([]string{"othergroup", "role:standard"}, groupings[1])
}

func (s *SQLAdapterSuite) TestParsePolicyCSV_EmptyLines() {
	csv := `

p, role:admin, *, *, allow

`

	policies, groupings := parsePolicyCSV(csv)

	s.Len(policies, 1)
	s.Empty(groupings)
}

func (s *SQLAdapterSuite) TestCreateV2EnforcerWithSQLAdapter() {
	gormDB := s.createTestGormDB()

	cfg := authz.CasbinV2Config{
		BaseAdapterConfig: authz.BaseAdapterConfig{
			GroupsClaim: "realm_access.roles",
		},
		GormDB: gormDB,
	}

	enforcer, err := createV2EnforcerFromConfig(cfg, s.logger)
	s.Require().NoError(err)
	s.Require().NotNil(enforcer)

	// Verify default policies were seeded
	policies, _ := enforcer.GetPolicy()
	s.NotEmpty(policies, "default policies should be seeded")
}

func (s *SQLAdapterSuite) TestCreateV2EnforcerWithCSVFallback() {
	// No GormDB provided, should fall back to CSV
	cfg := authz.CasbinV2Config{
		BaseAdapterConfig: authz.BaseAdapterConfig{
			GroupsClaim: "realm_access.roles",
		},
		// GormDB is nil
	}

	enforcer, err := createV2EnforcerFromConfig(cfg, s.logger)
	s.Require().NoError(err)
	s.Require().NotNil(enforcer)

	// Verify default policies loaded
	policies, _ := enforcer.GetPolicy()
	s.NotEmpty(policies, "default policies should be loaded from CSV")
}

func (s *SQLAdapterSuite) TestEnforcementParity_CSVvsSQLAdapter() {
	// Test policy
	testPolicy := `p, role:admin, *, *, allow
p, role:standard, /test/read, *, allow
g, admin-user, role:admin
g, standard-user, role:standard`

	// Create CSV-backed enforcer
	csvCfg := authz.CasbinV2Config{
		BaseAdapterConfig: authz.BaseAdapterConfig{
			GroupsClaim: "realm_access.roles",
		},
		Csv: testPolicy,
	}
	csvEnforcer, err := createV2EnforcerFromConfig(csvCfg, s.logger)
	s.Require().NoError(err)

	// Create SQL-backed enforcer
	gormDB := s.createTestGormDB()
	sqlCfg := authz.CasbinV2Config{
		BaseAdapterConfig: authz.BaseAdapterConfig{
			GroupsClaim: "realm_access.roles",
		},
		GormDB: gormDB,
		Csv:    testPolicy, // Will be used for seeding
	}
	sqlEnforcer, err := createV2EnforcerFromConfig(sqlCfg, s.logger)
	s.Require().NoError(err)

	// Test cases for enforcement parity
	testCases := []struct {
		subject string
		rpc     string
		dims    string
		allowed bool
	}{
		{"role:admin", "/any/path", "*", true},
		{"role:standard", "/test/read", "*", true},
		{"role:standard", "/test/write", "*", false},
		{"role:unknown", "/any/path", "*", false},
	}

	for _, tc := range testCases {
		csvResult, csvErr := csvEnforcer.Enforce(tc.subject, tc.rpc, tc.dims)
		sqlResult, sqlErr := sqlEnforcer.Enforce(tc.subject, tc.rpc, tc.dims)

		s.NoError(csvErr, "CSV enforcement should not error")
		s.NoError(sqlErr, "SQL enforcement should not error")
		s.Equal(csvResult, sqlResult, "Enforcement results should match for subject=%s, rpc=%s", tc.subject, tc.rpc)
		s.Equal(tc.allowed, csvResult, "Expected result for subject=%s, rpc=%s", tc.subject, tc.rpc)
	}
}

// createTestGormDB creates a file-based SQLite database for testing
// Using file-based SQLite because in-memory SQLite doesn't share between connections
func (s *SQLAdapterSuite) createTestGormDB() *gorm.DB {
	dbPath := s.tempDir + "/test.db"
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	s.Require().NoError(err)

	// Create casbin_rule table (normally done by goose migrations)
	err = db.AutoMigrate(&casbinRuleForTest{})
	s.Require().NoError(err)

	return db
}
