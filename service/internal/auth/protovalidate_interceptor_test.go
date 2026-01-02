package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/common"
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
