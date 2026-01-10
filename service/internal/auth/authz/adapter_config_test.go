package authz

import (
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/stretchr/testify/assert"
)

func TestEngineTypeConstants(t *testing.T) {
	assert.Equal(t, EngineCasbin, EngineType("casbin"))
}

func TestBaseAdapterConfig(t *testing.T) {
	cfg := BaseAdapterConfig{
		UserNameClaim: "preferred_username",
		GroupsClaim:   "realm_access.roles",
		ClientIDClaim: "azp",
	}

	assert.Equal(t, "preferred_username", cfg.UserNameClaim)
	assert.Equal(t, "realm_access.roles", cfg.GroupsClaim)
	assert.Equal(t, "azp", cfg.ClientIDClaim)
	assert.Nil(t, cfg.Logger)
}

func TestAdapterConfigFromExternal_CasbinV1(t *testing.T) {
	cfg := Config{
		Engine:  "casbin",
		Version: "v1",
		PolicyConfig: PolicyConfig{
			UserNameClaim: "sub",
			GroupsClaim:   "roles",
			ClientIDClaim: "client_id",
			Csv:           "p, role:admin, *, *, allow",
			Extension:     "p, role:test, /test, read, allow",
			Model:         "custom-model",
			RoleMap:       map[string]string{"ext-admin": "admin"},
		},
	}

	result := AdapterConfigFromExternal(cfg)

	v1Config, ok := result.(CasbinV1Config)
	assert.True(t, ok, "Expected CasbinV1Config")
	assert.Equal(t, "sub", v1Config.UserNameClaim)
	assert.Equal(t, "roles", v1Config.GroupsClaim)
	assert.Equal(t, "client_id", v1Config.ClientIDClaim)
	assert.Equal(t, "p, role:admin, *, *, allow", v1Config.Csv)
	assert.Equal(t, "p, role:test, /test, read, allow", v1Config.Extension)
	assert.Equal(t, "custom-model", v1Config.Model)
	assert.Equal(t, map[string]string{"ext-admin": "admin"}, v1Config.RoleMap)
	assert.Nil(t, v1Config.Adapter)
	assert.Nil(t, v1Config.Enforcer)
}

func TestAdapterConfigFromExternal_CasbinV2(t *testing.T) {
	cfg := Config{
		Engine:  "casbin",
		Version: "v2",
		PolicyConfig: PolicyConfig{
			UserNameClaim: "sub",
			GroupsClaim:   "roles",
			ClientIDClaim: "client_id",
			Csv:           "p, role:admin, *, *, allow",
			Extension:     "p, role:test, /test, read, allow",
			Model:         "custom-v2-model",
			RoleMap:       map[string]string{"ext-admin": "admin"},
		},
	}

	result := AdapterConfigFromExternal(cfg)

	v2Config, ok := result.(CasbinV2Config)
	assert.True(t, ok, "Expected CasbinV2Config")
	assert.Equal(t, "sub", v2Config.UserNameClaim)
	assert.Equal(t, "roles", v2Config.GroupsClaim)
	assert.Equal(t, "client_id", v2Config.ClientIDClaim)
	assert.Equal(t, "p, role:admin, *, *, allow", v2Config.Csv)
	assert.Equal(t, "p, role:test, /test, read, allow", v2Config.Extension)
	assert.Equal(t, "custom-v2-model", v2Config.Model)
	assert.Equal(t, map[string]string{"ext-admin": "admin"}, v2Config.RoleMap)
	assert.Nil(t, v2Config.Adapter)
}

func TestAdapterConfigFromExternal_DefaultEngine(t *testing.T) {
	// Empty engine should default to casbin
	cfg := Config{
		Engine:  "",
		Version: "v1",
	}

	result := AdapterConfigFromExternal(cfg)

	_, ok := result.(CasbinV1Config)
	assert.True(t, ok, "Expected CasbinV1Config with empty engine")
}

func TestAdapterConfigFromExternal_DefaultVersion(t *testing.T) {
	// Empty version should default to v1
	cfg := Config{
		Engine:  "casbin",
		Version: "",
	}

	result := AdapterConfigFromExternal(cfg)

	_, ok := result.(CasbinV1Config)
	assert.True(t, ok, "Expected CasbinV1Config with empty version")
}

func TestAdapterConfigFromExternal_UnknownEngine(t *testing.T) {
	// Unknown engine should fall back to casbin v1
	cfg := Config{
		Engine:  "unknown-engine",
		Version: "v1",
	}

	result := AdapterConfigFromExternal(cfg)

	_, ok := result.(CasbinV1Config)
	assert.True(t, ok, "Expected CasbinV1Config for unknown engine")
}

func TestAdapterConfigFromExternal_WithV1Enforcer(t *testing.T) {
	mockEnforcer := &mockV1Enforcer{}

	cfg := Config{
		Engine:  "casbin",
		Version: "v1",
		Options: []Option{WithV1Enforcer(mockEnforcer)},
	}

	result := AdapterConfigFromExternal(cfg)

	v1Config, ok := result.(CasbinV1Config)
	assert.True(t, ok)
	assert.Equal(t, mockEnforcer, v1Config.Enforcer)
}

func TestAdapterConfigFromExternal_WithAdapter(t *testing.T) {
	mockAdpt := &mockAdapter{}

	cfg := Config{
		Engine:  "casbin",
		Version: "v2",
		PolicyConfig: PolicyConfig{
			Adapter: mockAdpt,
		},
	}

	result := AdapterConfigFromExternal(cfg)

	v2Config, ok := result.(CasbinV2Config)
	assert.True(t, ok)
	assert.Equal(t, mockAdpt, v2Config.Adapter)
}

func TestAdapterFromAny_Nil(t *testing.T) {
	result := adapterFromAny(nil)
	assert.Nil(t, result)
}

func TestAdapterFromAny_ValidAdapter(t *testing.T) {
	mockAdpt := &mockAdapter{}
	result := adapterFromAny(mockAdpt)
	assert.Equal(t, mockAdpt, result)
}

func TestAdapterFromAny_InvalidType(t *testing.T) {
	result := adapterFromAny("not an adapter")
	assert.Nil(t, result)
}

func TestCasbinV1Config_Struct(t *testing.T) {
	cfg := CasbinV1Config{
		BaseAdapterConfig: BaseAdapterConfig{
			UserNameClaim: "sub",
		},
		Csv: "p, role:admin, *, *, allow",
	}

	// Verify all fields are accessible and have expected values
	assert.Equal(t, "sub", cfg.UserNameClaim)
	assert.Equal(t, "p, role:admin, *, *, allow", cfg.Csv)
	assert.Empty(t, cfg.Extension)
	assert.Empty(t, cfg.Model)
	assert.Nil(t, cfg.RoleMap)
	assert.Nil(t, cfg.Adapter)
	assert.Nil(t, cfg.Enforcer)
}

func TestCasbinV2Config_Struct(t *testing.T) {
	cfg := CasbinV2Config{
		BaseAdapterConfig: BaseAdapterConfig{
			UserNameClaim: "sub",
		},
		Csv: "p, role:admin, *, *, allow",
	}

	// Verify all fields are accessible and have expected values
	assert.Equal(t, "sub", cfg.UserNameClaim)
	assert.Equal(t, "p, role:admin, *, *, allow", cfg.Csv)
	assert.Empty(t, cfg.Extension)
	assert.Empty(t, cfg.Model)
	assert.Nil(t, cfg.RoleMap)
	assert.Nil(t, cfg.Adapter)
}

// mockAdapter implements persist.Adapter for testing
type mockAdapter struct{}

func (m *mockAdapter) LoadPolicy(_ model.Model) error {
	return nil
}

func (m *mockAdapter) SavePolicy(_ model.Model) error {
	return nil
}

func (m *mockAdapter) AddPolicy(_, _ string, _ []string) error {
	return nil
}

func (m *mockAdapter) RemovePolicy(_, _ string, _ []string) error {
	return nil
}

func (m *mockAdapter) RemoveFilteredPolicy(_, _ string, _ int, _ ...string) error {
	return nil
}

// Verify at compile time that mockAdapter implements persist.Adapter
var _ persist.Adapter = (*mockAdapter)(nil)
