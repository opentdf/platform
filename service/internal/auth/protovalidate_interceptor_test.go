package auth

import (
    "context"
    "testing"

    "connectrpc.com/connect"
    "github.com/stretchr/testify/require"
    "github.com/opentdf/platform/protocol/go/common"
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
