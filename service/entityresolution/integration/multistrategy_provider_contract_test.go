package integration

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	multistrategyv2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/testcontainers/testcontainers-go"

	_ "github.com/mattn/go-sqlite3"
)

type multiStrategyProviderContractAdapter struct {
	name         string
	config       types.MultiStrategyConfig
	expectations []internal.ResolvedTokenChainExpectation
	setup        func(context.Context) error
	teardown     func(context.Context) error
}

func (a *multiStrategyProviderContractAdapter) GetScopeName() string {
	return a.name
}

func (a *multiStrategyProviderContractAdapter) SetupTestData(ctx context.Context, _ *internal.ContractTestDataSet) error {
	if a.setup == nil {
		return nil
	}
	return a.setup(ctx)
}

func (a *multiStrategyProviderContractAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	return multistrategyv2.NewERSV2(ctx, a.config, logger.CreateTestLogger())
}

func (a *multiStrategyProviderContractAdapter) CreateERSServiceWithReversedStrategies(ctx context.Context) (internal.ERSImplementation, error) {
	config := a.config
	config.MappingStrategies = slices.Clone(a.config.MappingStrategies)
	slices.Reverse(config.MappingStrategies)
	return multistrategyv2.NewERSV2(ctx, config, logger.CreateTestLogger())
}

func (a *multiStrategyProviderContractAdapter) TeardownTestData(ctx context.Context) error {
	if a.teardown == nil {
		return nil
	}
	return a.teardown(ctx)
}

func (a *multiStrategyProviderContractAdapter) ResolvedTokenChainExpectations(_ *internal.ContractTestDataSet) []internal.ResolvedTokenChainExpectation {
	return a.expectations
}

func TestMultiStrategyProviderResolvedTokenChainContract(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-strategy provider contract tests in short mode")
	}

	adapters := []internal.ResolvedTokenChainAdapter{
		newClaimsProviderContractAdapter(),
		newSQLProviderContractAdapter(t),
		newLDAPProviderContractAdapter(t),
	}
	suite := internal.NewResolvedTokenChainContractSuite()
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.GetScopeName(), func(t *testing.T) {
			suite.RunWithAdapter(t, adapter)
		})
	}
}

func newClaimsProviderContractAdapter() *multiStrategyProviderContractAdapter {
	return &multiStrategyProviderContractAdapter{
		name: "ClaimsProvider",
		config: types.MultiStrategyConfig{
			FailureStrategy: types.FailureStrategyContinue,
			Providers: map[string]types.ProviderConfig{
				"claims": {Type: "claims", Connection: map[string]interface{}{}},
			},
			MappingStrategies: []types.MappingStrategy{
				environmentContractStrategy("claims"),
				{
					Name:       "claims_subject",
					Provider:   "claims",
					EntityType: types.EntityTypeSubject,
					Conditions: types.StrategyConditions{JWTClaims: []types.JWTClaimCondition{{Claim: "sub", Operator: "exists"}}},
					OutputMapping: []types.OutputMapping{
						{SourceClaim: "sub", ClaimName: "username"},
						{SourceClaim: "email", ClaimName: "email"},
						{SourceClaim: "department", ClaimName: "department"},
						{SourceClaim: "groups", ClaimName: "groups"},
					},
				},
			},
		},
		expectations: providerContractExpectations("claims", "alice@opentdf.test", "engineering", []interface{}{"engineering", "developers"}, "bob@opentdf.test", "marketing", []interface{}{"marketing", "campaigns"}),
	}
}

func newSQLProviderContractAdapter(t *testing.T) *multiStrategyProviderContractAdapter {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "ers-provider-contract.db")
	adapter := &multiStrategyProviderContractAdapter{
		name: "SQLProvider",
		config: types.MultiStrategyConfig{
			FailureStrategy: types.FailureStrategyContinue,
			Providers: map[string]types.ProviderConfig{
				"chain_context": {Type: "claims", Connection: map[string]interface{}{}},
				"sql": {Type: "sql", Connection: map[string]interface{}{
					"driver": "sqlite3", "database": databasePath,
				}},
			},
			MappingStrategies: []types.MappingStrategy{
				environmentContractStrategy("chain_context"),
				{
					Name:       "sql_subject",
					Provider:   "sql",
					EntityType: types.EntityTypeSubject,
					Conditions: types.StrategyConditions{JWTClaims: []types.JWTClaimCondition{{Claim: "sub", Operator: "exists"}}},
					Query:      "SELECT username, email, department, groups_csv FROM users WHERE username = ?",
					InputMapping: []types.InputMapping{{
						JWTClaim: "sub", Parameter: "username", Required: true,
					}},
					OutputMapping: []types.OutputMapping{
						{SourceColumn: "username", ClaimName: "username"},
						{SourceColumn: "email", ClaimName: "email"},
						{SourceColumn: "department", ClaimName: "department"},
						{SourceColumn: "groups_csv", ClaimName: "groups", Transformation: "csv_to_array"},
					},
				},
			},
		},
		expectations: providerContractExpectations("sql", "alice@opentdf.test", "engineering", []interface{}{"engineering", "developers"}, "bob@opentdf.test", "marketing", []interface{}{"marketing", "campaigns"}),
	}
	adapter.setup = func(context.Context) error {
		db, err := sql.Open("sqlite3", databasePath)
		if err != nil {
			return err
		}
		defer db.Close()
		_, err = db.Exec(`
			CREATE TABLE users (username TEXT PRIMARY KEY, email TEXT, department TEXT, groups_csv TEXT);
			INSERT INTO users VALUES ('alice', 'alice@opentdf.test', 'engineering', 'engineering,developers');
			INSERT INTO users VALUES ('bob', 'bob@opentdf.test', 'marketing', 'marketing,campaigns');
		`)
		return err
	}
	return adapter
}

func newLDAPProviderContractAdapter(t *testing.T) *multiStrategyProviderContractAdapter {
	t.Helper()
	adapter := &multiStrategyProviderContractAdapter{
		name:         "LDAPProvider",
		expectations: providerContractExpectations("ldap", "alice@opentdf.test", "engineering", []interface{}{"engineering", "developers"}, "bob@opentdf.test", "marketing", []interface{}{"marketing", "campaigns"}),
	}
	var container testcontainers.Container
	adapter.setup = func(ctx context.Context) error {
		var host string
		var port int
		container, host, port = startSeededLDAPContainer(ctx, t)
		adapter.config = types.MultiStrategyConfig{
			FailureStrategy: types.FailureStrategyContinue,
			Providers: map[string]types.ProviderConfig{
				"chain_context": {Type: "claims", Connection: map[string]interface{}{}},
				"ldap": {Type: "ldap", Connection: map[string]interface{}{
					"host": host, "port": port, "use_tls": false,
					"bind_dn": "cn=admin,dc=opentdf,dc=test", "bind_password": "admin123",
				}},
			},
			MappingStrategies: []types.MappingStrategy{
				environmentContractStrategy("chain_context"),
				{
					Name:       "ldap_subject",
					Provider:   "ldap",
					EntityType: types.EntityTypeSubject,
					Conditions: types.StrategyConditions{JWTClaims: []types.JWTClaimCondition{{Claim: "sub", Operator: "exists"}}},
					InputMapping: []types.InputMapping{{
						JWTClaim: "sub", Parameter: "username", Required: true,
					}},
					LDAPSearch: &types.LDAPSearchConfig{
						BaseDN: "ou=users,dc=opentdf,dc=test",
						Filter: "(&(objectClass=inetOrgPerson)(uid={username}))",
						Scope:  "subtree", Attributes: []string{"uid", "mail", "departmentNumber", "businessCategory"},
					},
					OutputMapping: []types.OutputMapping{
						{SourceAttribute: "uid", ClaimName: "username"},
						{SourceAttribute: "mail", ClaimName: "email"},
						{SourceAttribute: "departmentNumber", ClaimName: "department"},
						{SourceAttribute: "businessCategory", ClaimName: "groups"},
					},
				},
			},
		}
		return nil
	}
	adapter.teardown = func(ctx context.Context) error {
		if container == nil {
			return nil
		}
		return container.Terminate(ctx)
	}
	return adapter
}

func environmentContractStrategy(provider string) types.MappingStrategy {
	return types.MappingStrategy{
		Name:       "client_environment",
		Provider:   provider,
		EntityType: types.EntityTypeEnvironment,
		Conditions: types.StrategyConditions{JWTClaims: []types.JWTClaimCondition{{Claim: "client_id", Operator: "exists"}}},
		OutputMapping: []types.OutputMapping{
			{SourceClaim: "client_id", ClaimName: "client_id"},
		},
	}
}

func providerContractExpectations(provider, aliceEmail, aliceDepartment string, aliceGroups []interface{}, bobEmail, bobDepartment string, bobGroups []interface{}) []internal.ResolvedTokenChainExpectation {
	return []internal.ResolvedTokenChainExpectation{
		providerContractExpectation(provider+"-alice", "alice", aliceEmail, aliceDepartment, aliceGroups),
		providerContractExpectation(provider+"-bob", "bob", bobEmail, bobDepartment, bobGroups),
	}
}

func providerContractExpectation(tokenID, username, email, department string, groups []interface{}) internal.ResolvedTokenChainExpectation {
	return internal.ResolvedTokenChainExpectation{
		Token: &entity.Token{EphemeralId: tokenID, Jwt: internal.CreateTestJWTWithClaims("opentdf-sdk", username, email, map[string]interface{}{
			"department": department,
			"groups":     groups,
		})},
		Entities: []internal.ResolvedTokenChainEntityExpectation{
			{
				ExpectedClaims: map[string]interface{}{"client_id": "opentdf-sdk"},
				Category:       entity.Entity_CATEGORY_ENVIRONMENT,
			},
			{
				ExpectedClaims: map[string]interface{}{"username": username, "email": email, "department": department, "groups": groups},
				Category:       entity.Entity_CATEGORY_SUBJECT,
			},
		},
	}
}

var _ internal.ResolvedTokenChainAdapter = (*multiStrategyProviderContractAdapter)(nil)
