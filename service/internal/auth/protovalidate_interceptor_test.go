package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/stretchr/testify/suite"
)

func TestProtoAttrMapperSuite(t *testing.T) {
	suite.Run(t, new(ProtoAttrMapperSuite))
}

type ProtoAttrMapperSuite struct {
	suite.Suite
}

func (s *ProtoAttrMapperSuite) Test_Interceptor() {
	mapper := NewProtoAttrMapper([]string{"name", "id"}, nil, false)

	// create a simple proto message from policy namespace that has string fields
	msg := &common.IdNameIdentifier{
		Id:   "abc",
		Name: "example",
	}

	// create a no-op next handler that checks context for attrs
	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		v := ctx.Value(casbinContextKey("casbin_attrs"))
		s.Require().NotNil(v)
		m, ok := v.(map[string]string)
		s.Require().True(ok)
		s.Require().Equal("example", m["name"])
		s.Require().Equal("abc", m["id"])
		return connect.NewResponse[any](nil), nil
	}

	interceptor := mapper.Interceptor(nil)
	wrapped := interceptor(next)

	// Build a connect request wrapper
	req := connect.NewRequest(msg)
	_, err := wrapped(context.Background(), req)
	s.Require().NoError(err)
}

func (s *ProtoAttrMapperSuite) Test_RequiredFields_MissingFieldShouldFail() {
	mapper := NewProtoAttrMapper(
		[]string{"name", "id"},
		[]string{"name", "id"},
		false,
	)

	// Message missing 'name' field (empty string)
	msg := &common.IdNameIdentifier{
		Id:   "abc",
		Name: "", // empty/missing
	}

	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		s.T().Fatal("should not reach next handler")
		return connect.NewResponse[any](nil), nil
	}

	interceptor := mapper.Interceptor(nil)
	wrapped := interceptor(next)

	req := connect.NewRequest(msg)
	_, err := wrapped(context.Background(), req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "required field")
	s.Require().Contains(err.Error(), "name")
}

func (s *ProtoAttrMapperSuite) Test_RequiredFields_AllPresentShouldSucceed() {
	mapper := NewProtoAttrMapper(
		[]string{"name", "id"},
		[]string{"name"},
		false,
	)

	msg := &common.IdNameIdentifier{
		Id:   "abc",
		Name: "example",
	}

	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		v := ctx.Value(casbinContextKey("casbin_attrs"))
		s.Require().NotNil(v)
		return connect.NewResponse[any](nil), nil
	}

	interceptor := mapper.Interceptor(nil)
	wrapped := interceptor(next)

	req := connect.NewRequest(msg)
	_, err := wrapped(context.Background(), req)
	s.Require().NoError(err)
}

func (s *ProtoAttrMapperSuite) Test_WhitelistOnly() {
	// Only allow 'name', not 'id'
	mapper := NewProtoAttrMapper(
		[]string{"name"},
		nil,
		false,
	)

	msg := &common.IdNameIdentifier{
		Id:   "secret-id-should-not-be-exposed",
		Name: "example",
	}

	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		v := ctx.Value(casbinContextKey("casbin_attrs"))
		s.Require().NotNil(v)
		m, ok := v.(map[string]string)
		s.Require().True(ok)

		// SECURITY TEST: only 'name' should be present
		s.Require().Equal("example", m["name"])
		s.Require().NotContains(m, "id", "id should NOT be in attrs - security violation")
		s.Require().Len(m, 1, "only whitelisted fields should be present")
		return connect.NewResponse[any](nil), nil
	}

	interceptor := mapper.Interceptor(nil)
	wrapped := interceptor(next)

	req := connect.NewRequest(msg)
	_, err := wrapped(context.Background(), req)
	s.Require().NoError(err)
}

func (s *ProtoAttrMapperSuite) Test_AttributeExtraction() {
	mapper := NewProtoAttrMapper(
		[]string{"name", "id"},
		[]string{"id"},
		false,
	)

	msg := &common.IdNameIdentifier{
		Id:   "user123",
		Name: "test-resource",
	}

	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		v := ctx.Value(casbinContextKey("casbin_attrs"))
		s.Require().NotNil(v)
		attrs, ok := v.(map[string]string)
		s.Require().True(ok)

		// Verify extracted attributes are ready for enforcement
		s.Require().Equal("user123", attrs["id"])
		s.Require().Equal("test-resource", attrs["name"])

		// These attrs can now be passed to Casbin Enforce with extended signature
		// e.g., enforcer.Enforce(subject, resource, action, attrs["id"])
		return connect.NewResponse[any](nil), nil
	}

	interceptor := mapper.Interceptor(nil)
	wrapped := interceptor(next)

	req := connect.NewRequest(msg)
	_, err := wrapped(context.Background(), req)
	s.Require().NoError(err)
}
