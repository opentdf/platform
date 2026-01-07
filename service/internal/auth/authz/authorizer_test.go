package authz

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModeConstants(t *testing.T) {
	// Verify mode constants have expected values
	assert.Equal(t, ModeV1, Mode("v1"))
	assert.Equal(t, ModeV2, Mode("v2"))
}

func TestDefaultEngine(t *testing.T) {
	assert.Equal(t, "casbin", DefaultEngine)
}

func TestRequestStruct(t *testing.T) {
	// Test that Request struct can be constructed with all fields
	dims := make(map[string]string)
	dims["namespace"] = "test"
	resource := ResolverResource(dims)

	req := Request{
		RPC:    "/test.Service/Method",
		Action: "read",
		ResourceContext: &ResolverContext{
			Resources: []*ResolverResource{&resource},
		},
	}

	assert.Equal(t, "/test.Service/Method", req.RPC)
	assert.Equal(t, "read", req.Action)
	assert.NotNil(t, req.ResourceContext)
	assert.Len(t, req.ResourceContext.Resources, 1)
}

func TestDecisionStruct(t *testing.T) {
	// Test that Decision struct can be constructed with all fields
	decision := Decision{
		Allowed:       true,
		Reason:        "test reason",
		Mode:          ModeV2,
		MatchedPolicy: "role:admin",
	}

	assert.True(t, decision.Allowed)
	assert.Equal(t, "test reason", decision.Reason)
	assert.Equal(t, ModeV2, decision.Mode)
	assert.Equal(t, "role:admin", decision.MatchedPolicy)
}

func TestRegisterAndGetFactory(t *testing.T) {
	// Use a unique factory name to avoid conflicts with other tests
	testFactoryName := "test-factory-register"

	// Test factory that returns a mock authorizer
	testFactory := func(cfg Config) (Authorizer, error) {
		return &mockAuthorizer{version: cfg.Version}, nil
	}

	// Register the factory
	RegisterFactory(testFactoryName, testFactory)

	// Get the factory back
	factory, exists := GetFactory(testFactoryName)
	require.True(t, exists)
	require.NotNil(t, factory)

	// Test that the factory works
	auth, err := factory(Config{Version: "v1"})
	require.NoError(t, err)
	assert.Equal(t, "v1", auth.Version())
}

func TestGetFactory_NotFound(t *testing.T) {
	factory, exists := GetFactory("non-existent-factory")
	assert.False(t, exists)
	assert.Nil(t, factory)
}

func TestRegisterFactory_Panic_OnDuplicate(t *testing.T) {
	// Use a unique factory name
	testFactoryName := "test-factory-duplicate"

	testFactory := func(_ Config) (Authorizer, error) {
		return &mockAuthorizer{}, nil
	}

	// First registration should succeed
	RegisterFactory(testFactoryName, testFactory)

	// Second registration with same name should panic
	assert.Panics(t, func() {
		RegisterFactory(testFactoryName, testFactory)
	})
}

func TestNew_UnregisteredEngine(t *testing.T) {
	cfg := Config{
		Engine:  "unregistered-engine",
		Version: "v1",
	}

	auth, err := New(cfg)
	require.Error(t, err)
	assert.Nil(t, auth)
	assert.Contains(t, err.Error(), "not registered")
}

func TestNew_DefaultValues(t *testing.T) {
	// Register a test factory for this test
	testFactoryName := "test-factory-defaults"
	var receivedCfg Config

	testFactory := func(cfg Config) (Authorizer, error) {
		receivedCfg = cfg
		return &mockAuthorizer{version: cfg.Version}, nil
	}

	RegisterFactory(testFactoryName, testFactory)

	// Call New with minimal config (but specify engine so we use our test factory)
	cfg := Config{
		Engine: testFactoryName,
	}

	auth, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, auth)

	// Verify defaults were applied
	assert.Equal(t, "v1", receivedCfg.Version, "Version should default to v1")
}

func TestWithV1Enforcer(t *testing.T) {
	mockEnforcer := &mockV1Enforcer{}

	opt := WithV1Enforcer(mockEnforcer)
	cfg := applyOptions(opt)

	assert.Equal(t, mockEnforcer, cfg.V1Enforcer)
}

func TestApplyOptions_Empty(t *testing.T) {
	cfg := applyOptions()
	assert.Nil(t, cfg.V1Enforcer)
}

func TestApplyOptions_Multiple(t *testing.T) {
	mockEnforcer := &mockV1Enforcer{}

	cfg := applyOptions(
		WithV1Enforcer(mockEnforcer),
	)

	assert.Equal(t, mockEnforcer, cfg.V1Enforcer)
}

// mockAuthorizer implements Authorizer for testing
type mockAuthorizer struct {
	version              string
	supportsResourceAuth bool
	authorizeFunc        func(ctx context.Context, req *Request) (*Decision, error)
}

func (m *mockAuthorizer) Authorize(ctx context.Context, req *Request) (*Decision, error) {
	if m.authorizeFunc != nil {
		return m.authorizeFunc(ctx, req)
	}
	return &Decision{Allowed: true, Mode: ModeV1}, nil
}

func (m *mockAuthorizer) Version() string {
	if m.version == "" {
		return "v1"
	}
	return m.version
}

func (m *mockAuthorizer) SupportsResourceAuthorization() bool {
	return m.supportsResourceAuth
}

// mockV1Enforcer implements V1Enforcer for testing
type mockV1Enforcer struct {
	enforceResult bool
	subjects      []string
}

func (m *mockV1Enforcer) Enforce(_ jwt.Token, _ []byte, _, _ string) bool {
	return m.enforceResult
}

func (m *mockV1Enforcer) BuildSubjectFromTokenAndUserInfo(_ jwt.Token, _ []byte) []string {
	if m.subjects != nil {
		return m.subjects
	}
	return []string{"role:test"}
}
