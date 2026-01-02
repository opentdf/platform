package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
)

func Test_ProtoAttrMapper_Interceptor(t *testing.T) {
	mapper := &ProtoAttrMapper{Allowed: []string{"name", "id"}, Validate: false}

	// create a simple proto message from policy namespace that has string fields
	msg := &common.IdNameIdentifier{
		Id:   "abc",
		Name: "example",
	}

	// create a no-op next handler that checks context for attrs
	next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		v := ctx.Value(casbinContextKey("casbin_attrs"))
		require.NotNil(t, v)
		m, ok := v.(map[string]string)
		require.True(t, ok)
		require.Equal(t, "example", m["name"])
		require.Equal(t, "abc", m["id"])
		return connect.NewResponse[any](nil), nil
	}

	interceptor := mapper.Interceptor(nil)
	wrapped := interceptor(next)

	// Build a connect request wrapper
	req := connect.NewRequest(msg)
	_, err := wrapped(context.Background(), req)
	require.NoError(t, err)
}

func Test_ProtoAttrMapper_RequiredFields(t *testing.T) {
	t.Run("missing required field should fail", func(t *testing.T) {
		mapper := &ProtoAttrMapper{
			Allowed:        []string{"name", "id"},
			RequiredFields: []string{"name", "id"},
			Validate:       false,
		}

		// Message missing 'name' field (empty string)
		msg := &common.IdNameIdentifier{
			Id:   "abc",
			Name: "", // empty/missing
		}

		next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			t.Fatal("should not reach next handler")
			return connect.NewResponse[any](nil), nil
		}

		interceptor := mapper.Interceptor(nil)
		wrapped := interceptor(next)

		req := connect.NewRequest(msg)
		_, err := wrapped(context.Background(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "required field")
		require.Contains(t, err.Error(), "name")
	})

	t.Run("all required fields present should succeed", func(t *testing.T) {
		mapper := &ProtoAttrMapper{
			Allowed:        []string{"name", "id"},
			RequiredFields: []string{"name"},
			Validate:       false,
		}

		msg := &common.IdNameIdentifier{
			Id:   "abc",
			Name: "example",
		}

		next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			v := ctx.Value(casbinContextKey("casbin_attrs"))
			require.NotNil(t, v)
			return connect.NewResponse[any](nil), nil
		}

		interceptor := mapper.Interceptor(nil)
		wrapped := interceptor(next)

		req := connect.NewRequest(msg)
		_, err := wrapped(context.Background(), req)
		require.NoError(t, err)
	})
}

func Test_ProtoAttrMapper_WhitelistOnly(t *testing.T) {
	t.Run("only whitelisted fields should be in attrs", func(t *testing.T) {
		// Only allow 'name', not 'id'
		mapper := &ProtoAttrMapper{
			Allowed:  []string{"name"},
			Validate: false,
		}

		msg := &common.IdNameIdentifier{
			Id:   "secret-id-should-not-be-exposed",
			Name: "example",
		}

		next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			v := ctx.Value(casbinContextKey("casbin_attrs"))
			require.NotNil(t, v)
			m, ok := v.(map[string]string)
			require.True(t, ok)

			// SECURITY TEST: only 'name' should be present
			require.Equal(t, "example", m["name"])
			require.NotContains(t, m, "id", "id should NOT be in attrs - security violation")
			require.Len(t, m, 1, "only whitelisted fields should be present")
			return connect.NewResponse[any](nil), nil
		}

		interceptor := mapper.Interceptor(nil)
		wrapped := interceptor(next)

		req := connect.NewRequest(msg)
		_, err := wrapped(context.Background(), req)
		require.NoError(t, err)
	})
}

func Test_ProtoAttrMapper_EnforcementIntegration(t *testing.T) {
	t.Run("enforcement with attribute-based policy", func(t *testing.T) {
		// Create a Casbin enforcer with an attribute-aware model
		modelConf := `
[request_definition]
r = sub, res, act, owner

[policy_definition]
p = sub, res, act, owner, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.res, p.res) && keyMatch(r.act, p.act) && (p.owner == "*" || r.owner == p.owner)
`

		policyCSV := `
p, role:admin, /policy/*, read, *, allow
p, role:user, /policy/*, read, user123, allow
g, admin-user, role:admin
g, regular-user, role:user
`
		loggerInstance, err := logger.NewLogger(logger.Config{
			Level:  "error",
			Output: "stdout",
			Type:   "json",
		})
		require.NoError(t, err)
		require.NotNil(t, loggerInstance)

		casbinCfg := CasbinConfig{
			PolicyConfig: PolicyConfig{
				Model: modelConf,
				Csv:   policyCSV,
			},
		}
		enforcer, err := NewCasbinEnforcer(casbinCfg, loggerInstance)
		require.NoError(t, err)
		require.NotNil(t, enforcer)

		// Test 1: Admin can access any resource
		allowed, err := enforcer.Enforcer.Enforce("role:admin", "/policy/attributes", "read", "*")
		require.NoError(t, err)
		require.True(t, allowed, "admin should have access")

		// Test 2: User can only access their own resources
		allowed, err = enforcer.Enforcer.Enforce("role:user", "/policy/attributes", "read", "user123")
		require.NoError(t, err)
		require.True(t, allowed, "user should have access to their own resource")

		// Test 3: User cannot access other user's resources
		allowed, err = enforcer.Enforcer.Enforce("role:user", "/policy/attributes", "read", "user456")
		require.NoError(t, err)
		require.False(t, allowed, "user should NOT have access to other user's resource")

		t.Log("Attribute-based enforcement working correctly")
	})

	t.Run("interceptor extracts attrs for enforcement", func(t *testing.T) {
		mapper := &ProtoAttrMapper{
			Allowed:        []string{"name", "id"},
			RequiredFields: []string{"id"},
			Validate:       false,
		}

		msg := &common.IdNameIdentifier{
			Id:   "user123",
			Name: "test-resource",
		}

		next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			v := ctx.Value(casbinContextKey("casbin_attrs"))
			require.NotNil(t, v)
			attrs, ok := v.(map[string]string)
			require.True(t, ok)

			// Verify extracted attributes are ready for enforcement
			require.Equal(t, "user123", attrs["id"])
			require.Equal(t, "test-resource", attrs["name"])

			// These attrs can now be passed to Casbin Enforce with extended signature
			// e.g., enforcer.Enforce(subject, resource, action, attrs["id"])
			return connect.NewResponse[any](nil), nil
		}

		interceptor := mapper.Interceptor(nil)
		wrapped := interceptor(next)

		req := connect.NewRequest(msg)
		_, err := wrapped(context.Background(), req)
		require.NoError(t, err)
	})
}
