package auth

import (
	"context"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
)

// Test suite for AuthzResolver functionality
type AuthzResolverSuite struct {
	suite.Suite
}

func TestAuthzResolverSuite(t *testing.T) {
	suite.Run(t, new(AuthzResolverSuite))
}

// --- AuthzResolverRegistry Tests ---

func (s *AuthzResolverSuite) TestNewAuthzResolverRegistry() {
	registry := NewAuthzResolverRegistry()

	s.NotNil(registry)
	s.NotNil(registry.resolvers)
	s.Empty(registry.resolvers)
}

func (s *AuthzResolverSuite) TestRegistry_Get_NotFound() {
	registry := NewAuthzResolverRegistry()

	resolver, ok := registry.Get("/service.Method")
	s.False(ok)
	s.Nil(resolver)
}

func (s *AuthzResolverSuite) TestRegistry_RegisterAndGet() {
	registry := NewAuthzResolverRegistry()
	called := false
	testResolver := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		called = true
		return NewAuthzResolverContext(), nil
	}

	// Use internal register method (normally called via scoped registry)
	registry.register("/test.Service/TestMethod", testResolver)

	resolver, ok := registry.Get("/test.Service/TestMethod")
	s.True(ok)
	s.NotNil(resolver)

	// Verify the resolver is the same by calling it
	_, _ = resolver(context.Background(), nil)
	s.True(called)
}

func (s *AuthzResolverSuite) TestRegistry_ThreadSafety() {
	registry := NewAuthzResolverRegistry()
	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // readers and writers

	// Writers
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range numOperations {
				methodPath := "/test.Service/Method" + string(rune('A'+id%26)) + string(rune('0'+j%10))
				registry.register(methodPath, func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
					return NewAuthzResolverContext(), nil
				})
			}
		}(i)
	}

	// Readers
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for range numOperations {
				registry.Get("/test.Service/MethodA0")
			}
		}()
	}

	// Should complete without race conditions
	wg.Wait()
}

// --- ScopedAuthzResolverRegistry Tests ---

func (s *AuthzResolverSuite) TestScopedForService_NilServiceDesc_Panics() {
	registry := NewAuthzResolverRegistry()

	s.Panics(func() {
		registry.ScopedForService(nil)
	})
}

func (s *AuthzResolverSuite) TestScopedForService_ValidServiceDesc() {
	registry := NewAuthzResolverRegistry()
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "test.TestService",
		Methods: []grpc.MethodDesc{
			{MethodName: "GetThing"},
			{MethodName: "CreateThing"},
		},
	}

	scoped := registry.ScopedForService(serviceDesc)

	s.NotNil(scoped)
	s.Equal("test.TestService", scoped.ServiceName())
	s.Same(registry, scoped.parent)
}

func (s *AuthzResolverSuite) TestScoped_Register_ValidMethod() {
	registry := NewAuthzResolverRegistry()
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "policy.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "CreateAttribute"},
			{MethodName: "GetAttribute"},
		},
	}
	scoped := registry.ScopedForService(serviceDesc)

	testResolver := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		return NewAuthzResolverContext(), nil
	}

	err := scoped.Register("CreateAttribute", testResolver)

	s.Require().NoError(err)

	// Verify it was registered with full path
	resolver, ok := registry.Get("/policy.AttributesService/CreateAttribute")
	s.True(ok)
	s.NotNil(resolver)
}

func (s *AuthzResolverSuite) TestScoped_Register_InvalidMethod() {
	registry := NewAuthzResolverRegistry()
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "policy.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "CreateAttribute"},
		},
	}
	scoped := registry.ScopedForService(serviceDesc)

	testResolver := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		return NewAuthzResolverContext(), nil
	}

	err := scoped.Register("NonExistentMethod", testResolver)

	s.Require().Error(err)
	s.Contains(err.Error(), "method \"NonExistentMethod\" not found in service \"policy.AttributesService\"")

	// Verify nothing was registered
	_, ok := registry.Get("/policy.AttributesService/NonExistentMethod")
	s.False(ok)
}

func (s *AuthzResolverSuite) TestScoped_MustRegister_ValidMethod() {
	registry := NewAuthzResolverRegistry()
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "policy.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "GetAttribute"},
		},
	}
	scoped := registry.ScopedForService(serviceDesc)

	testResolver := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		return NewAuthzResolverContext(), nil
	}

	// Should not panic
	s.NotPanics(func() {
		scoped.MustRegister("GetAttribute", testResolver)
	})

	// Verify registration
	resolver, ok := registry.Get("/policy.AttributesService/GetAttribute")
	s.True(ok)
	s.NotNil(resolver)
}

func (s *AuthzResolverSuite) TestScoped_MustRegister_InvalidMethod_Panics() {
	registry := NewAuthzResolverRegistry()
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "policy.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "GetAttribute"},
		},
	}
	scoped := registry.ScopedForService(serviceDesc)

	testResolver := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		return NewAuthzResolverContext(), nil
	}

	s.Panics(func() {
		scoped.MustRegister("InvalidMethod", testResolver)
	})
}

func (s *AuthzResolverSuite) TestScoped_MultipleServicesIsolation() {
	registry := NewAuthzResolverRegistry()

	serviceA := &grpc.ServiceDesc{
		ServiceName: "serviceA.ServiceA",
		Methods: []grpc.MethodDesc{
			{MethodName: "MethodA"},
		},
	}
	serviceB := &grpc.ServiceDesc{
		ServiceName: "serviceB.ServiceB",
		Methods: []grpc.MethodDesc{
			{MethodName: "MethodB"},
		},
	}

	scopedA := registry.ScopedForService(serviceA)
	scopedB := registry.ScopedForService(serviceB)

	resolverA := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		ctx := NewAuthzResolverContext()
		res := ctx.NewResource()
		res.AddDimension("service", "A")
		return ctx, nil
	}
	resolverB := func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		ctx := NewAuthzResolverContext()
		res := ctx.NewResource()
		res.AddDimension("service", "B")
		return ctx, nil
	}

	// Service A can only register for its own methods
	err := scopedA.Register("MethodA", resolverA)
	s.Require().NoError(err)

	err = scopedA.Register("MethodB", resolverA) // Should fail - MethodB not in ServiceA
	s.Require().Error(err)

	// Service B can only register for its own methods
	err = scopedB.Register("MethodB", resolverB)
	s.Require().NoError(err)

	err = scopedB.Register("MethodA", resolverB) // Should fail - MethodA not in ServiceB
	s.Require().Error(err)

	// Both registrations should exist in global registry with correct paths
	rA, okA := registry.Get("/serviceA.ServiceA/MethodA")
	s.True(okA)
	s.NotNil(rA)

	rB, okB := registry.Get("/serviceB.ServiceB/MethodB")
	s.True(okB)
	s.NotNil(rB)

	// Verify they're distinct resolvers
	ctxA, _ := rA(context.Background(), nil)
	ctxB, _ := rB(context.Background(), nil)

	s.Equal("A", (*ctxA.Resources[0])["service"])
	s.Equal("B", (*ctxB.Resources[0])["service"])
}

// --- AuthzResolverContext Tests ---

func (s *AuthzResolverSuite) TestNewAuthzResolverContext() {
	ctx := NewAuthzResolverContext()

	s.NotNil(ctx)
	s.Nil(ctx.Resources) // Should be nil initially, not empty slice
}

func (s *AuthzResolverSuite) TestAuthzResolverContext_NewResource() {
	ctx := NewAuthzResolverContext()

	res1 := ctx.NewResource()
	s.NotNil(res1)
	s.Len(ctx.Resources, 1)

	res2 := ctx.NewResource()
	s.NotNil(res2)
	s.Len(ctx.Resources, 2)

	// Verify they're different resources
	s.NotSame(res1, res2)
}

func (s *AuthzResolverSuite) TestAuthzResolverContext_MultipleResources() {
	ctx := NewAuthzResolverContext()

	// Simulate "move from namespace A to namespace B" scenario
	source := ctx.NewResource()
	source.AddDimension("namespace", "ns-source")
	source.AddDimension("operation", "read")

	destination := ctx.NewResource()
	destination.AddDimension("namespace", "ns-destination")
	destination.AddDimension("operation", "write")

	s.Len(ctx.Resources, 2)
	s.Equal("ns-source", (*ctx.Resources[0])["namespace"])
	s.Equal("ns-destination", (*ctx.Resources[1])["namespace"])
}

// --- AuthzResolverResource Tests ---

func (s *AuthzResolverSuite) TestAuthzResolverResource_AddDimension() {
	ctx := NewAuthzResolverContext()
	res := ctx.NewResource()

	res.AddDimension("namespace", "hr")
	res.AddDimension("action", "create")
	res.AddDimension("resource_type", "attribute")

	s.Equal("hr", (*res)["namespace"])
	s.Equal("create", (*res)["action"])
	s.Equal("attribute", (*res)["resource_type"])
}

func (s *AuthzResolverSuite) TestAuthzResolverResource_OverwriteDimension() {
	ctx := NewAuthzResolverContext()
	res := ctx.NewResource()

	res.AddDimension("namespace", "original")
	res.AddDimension("namespace", "updated")

	s.Equal("updated", (*res)["namespace"])
}

func (s *AuthzResolverSuite) TestAuthzResolverResource_EmptyValues() {
	ctx := NewAuthzResolverContext()
	res := ctx.NewResource()

	res.AddDimension("", "empty-key")
	res.AddDimension("empty-value", "")

	s.Equal("empty-key", (*res)[""])
	s.Empty((*res)["empty-value"])
}

// --- Integration Tests ---

func (s *AuthzResolverSuite) TestFullWorkflow_ServiceRegistration() {
	// Simulates how a service would use the registry during initialization
	registry := NewAuthzResolverRegistry()

	// Service descriptor (normally from proto-generated code)
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "policy.attributes.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "CreateAttribute"},
			{MethodName: "GetAttribute"},
			{MethodName: "UpdateAttribute"},
			{MethodName: "DeleteAttribute"},
			{MethodName: "ListAttributes"},
		},
	}

	// Platform creates scoped registry for service
	scopedRegistry := registry.ScopedForService(serviceDesc)

	// Service registers resolvers during initialization (like in RegisterFunc)
	scopedRegistry.MustRegister("CreateAttribute", func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		ctx := NewAuthzResolverContext()
		res := ctx.NewResource()
		res.AddDimension("namespace", "test-ns")
		res.AddDimension("action", "create")
		return ctx, nil
	})

	scopedRegistry.MustRegister("GetAttribute", func(_ context.Context, _ connect.AnyRequest) (AuthzResolverContext, error) {
		ctx := NewAuthzResolverContext()
		res := ctx.NewResource()
		res.AddDimension("namespace", "test-ns")
		res.AddDimension("action", "read")
		return ctx, nil
	})

	// Interceptor looks up resolvers by method path
	createResolver, ok := registry.Get("/policy.attributes.AttributesService/CreateAttribute")
	s.True(ok)

	getResolver, ok := registry.Get("/policy.attributes.AttributesService/GetAttribute")
	s.True(ok)

	// Methods without resolvers return false
	_, ok = registry.Get("/policy.attributes.AttributesService/ListAttributes")
	s.False(ok)

	// Verify resolver execution
	createCtx, err := createResolver(context.Background(), nil)
	s.Require().NoError(err)
	s.Len(createCtx.Resources, 1)
	s.Equal("create", (*createCtx.Resources[0])["action"])

	getCtx, err := getResolver(context.Background(), nil)
	s.Require().NoError(err)
	s.Len(getCtx.Resources, 1)
	s.Equal("read", (*getCtx.Resources[0])["action"])
}

// --- Additional Test Functions (non-suite) ---

func TestAuthzResolverRegistry_Basic(t *testing.T) {
	registry := NewAuthzResolverRegistry()
	require.NotNil(t, registry)
	assert.Empty(t, registry.resolvers)
}

func TestScopedRegistry_ServiceName(t *testing.T) {
	registry := NewAuthzResolverRegistry()
	serviceDesc := &grpc.ServiceDesc{
		ServiceName: "my.custom.Service",
		Methods:     []grpc.MethodDesc{{MethodName: "DoSomething"}},
	}

	scoped := registry.ScopedForService(serviceDesc)

	assert.Equal(t, "my.custom.Service", scoped.ServiceName())
}

func TestAuthzResolverContext_ResourceIndependence(t *testing.T) {
	ctx := NewAuthzResolverContext()

	res1 := ctx.NewResource()
	res1.AddDimension("key", "value1")

	res2 := ctx.NewResource()
	res2.AddDimension("key", "value2")

	// Modifying res1 shouldn't affect res2
	assert.Equal(t, "value1", (*res1)["key"])
	assert.Equal(t, "value2", (*res2)["key"])
}
