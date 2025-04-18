// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: policy/registeredresources/registered_resources.proto

package registeredresourcesconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	registeredresources "github.com/opentdf/platform/protocol/go/policy/registeredresources"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// RegisteredResourcesServiceName is the fully-qualified name of the RegisteredResourcesService
	// service.
	RegisteredResourcesServiceName = "policy.registeredresources.RegisteredResourcesService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// RegisteredResourcesServiceCreateRegisteredResourceProcedure is the fully-qualified name of the
	// RegisteredResourcesService's CreateRegisteredResource RPC.
	RegisteredResourcesServiceCreateRegisteredResourceProcedure = "/policy.registeredresources.RegisteredResourcesService/CreateRegisteredResource"
	// RegisteredResourcesServiceGetRegisteredResourceProcedure is the fully-qualified name of the
	// RegisteredResourcesService's GetRegisteredResource RPC.
	RegisteredResourcesServiceGetRegisteredResourceProcedure = "/policy.registeredresources.RegisteredResourcesService/GetRegisteredResource"
	// RegisteredResourcesServiceListRegisteredResourcesProcedure is the fully-qualified name of the
	// RegisteredResourcesService's ListRegisteredResources RPC.
	RegisteredResourcesServiceListRegisteredResourcesProcedure = "/policy.registeredresources.RegisteredResourcesService/ListRegisteredResources"
	// RegisteredResourcesServiceUpdateRegisteredResourceProcedure is the fully-qualified name of the
	// RegisteredResourcesService's UpdateRegisteredResource RPC.
	RegisteredResourcesServiceUpdateRegisteredResourceProcedure = "/policy.registeredresources.RegisteredResourcesService/UpdateRegisteredResource"
	// RegisteredResourcesServiceDeleteRegisteredResourceProcedure is the fully-qualified name of the
	// RegisteredResourcesService's DeleteRegisteredResource RPC.
	RegisteredResourcesServiceDeleteRegisteredResourceProcedure = "/policy.registeredresources.RegisteredResourcesService/DeleteRegisteredResource"
	// RegisteredResourcesServiceCreateRegisteredResourceValueProcedure is the fully-qualified name of
	// the RegisteredResourcesService's CreateRegisteredResourceValue RPC.
	RegisteredResourcesServiceCreateRegisteredResourceValueProcedure = "/policy.registeredresources.RegisteredResourcesService/CreateRegisteredResourceValue"
	// RegisteredResourcesServiceGetRegisteredResourceValueProcedure is the fully-qualified name of the
	// RegisteredResourcesService's GetRegisteredResourceValue RPC.
	RegisteredResourcesServiceGetRegisteredResourceValueProcedure = "/policy.registeredresources.RegisteredResourcesService/GetRegisteredResourceValue"
	// RegisteredResourcesServiceListRegisteredResourceValuesProcedure is the fully-qualified name of
	// the RegisteredResourcesService's ListRegisteredResourceValues RPC.
	RegisteredResourcesServiceListRegisteredResourceValuesProcedure = "/policy.registeredresources.RegisteredResourcesService/ListRegisteredResourceValues"
	// RegisteredResourcesServiceUpdateRegisteredResourceValueProcedure is the fully-qualified name of
	// the RegisteredResourcesService's UpdateRegisteredResourceValue RPC.
	RegisteredResourcesServiceUpdateRegisteredResourceValueProcedure = "/policy.registeredresources.RegisteredResourcesService/UpdateRegisteredResourceValue"
	// RegisteredResourcesServiceDeleteRegisteredResourceValueProcedure is the fully-qualified name of
	// the RegisteredResourcesService's DeleteRegisteredResourceValue RPC.
	RegisteredResourcesServiceDeleteRegisteredResourceValueProcedure = "/policy.registeredresources.RegisteredResourcesService/DeleteRegisteredResourceValue"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	registeredResourcesServiceServiceDescriptor                             = registeredresources.File_policy_registeredresources_registered_resources_proto.Services().ByName("RegisteredResourcesService")
	registeredResourcesServiceCreateRegisteredResourceMethodDescriptor      = registeredResourcesServiceServiceDescriptor.Methods().ByName("CreateRegisteredResource")
	registeredResourcesServiceGetRegisteredResourceMethodDescriptor         = registeredResourcesServiceServiceDescriptor.Methods().ByName("GetRegisteredResource")
	registeredResourcesServiceListRegisteredResourcesMethodDescriptor       = registeredResourcesServiceServiceDescriptor.Methods().ByName("ListRegisteredResources")
	registeredResourcesServiceUpdateRegisteredResourceMethodDescriptor      = registeredResourcesServiceServiceDescriptor.Methods().ByName("UpdateRegisteredResource")
	registeredResourcesServiceDeleteRegisteredResourceMethodDescriptor      = registeredResourcesServiceServiceDescriptor.Methods().ByName("DeleteRegisteredResource")
	registeredResourcesServiceCreateRegisteredResourceValueMethodDescriptor = registeredResourcesServiceServiceDescriptor.Methods().ByName("CreateRegisteredResourceValue")
	registeredResourcesServiceGetRegisteredResourceValueMethodDescriptor    = registeredResourcesServiceServiceDescriptor.Methods().ByName("GetRegisteredResourceValue")
	registeredResourcesServiceListRegisteredResourceValuesMethodDescriptor  = registeredResourcesServiceServiceDescriptor.Methods().ByName("ListRegisteredResourceValues")
	registeredResourcesServiceUpdateRegisteredResourceValueMethodDescriptor = registeredResourcesServiceServiceDescriptor.Methods().ByName("UpdateRegisteredResourceValue")
	registeredResourcesServiceDeleteRegisteredResourceValueMethodDescriptor = registeredResourcesServiceServiceDescriptor.Methods().ByName("DeleteRegisteredResourceValue")
)

// RegisteredResourcesServiceClient is a client for the
// policy.registeredresources.RegisteredResourcesService service.
type RegisteredResourcesServiceClient interface {
	CreateRegisteredResource(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error)
	GetRegisteredResource(context.Context, *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error)
	ListRegisteredResources(context.Context, *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error)
	UpdateRegisteredResource(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error)
	DeleteRegisteredResource(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error)
	CreateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error)
	GetRegisteredResourceValue(context.Context, *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error)
	ListRegisteredResourceValues(context.Context, *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error)
	UpdateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error)
	DeleteRegisteredResourceValue(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error)
}

// NewRegisteredResourcesServiceClient constructs a client for the
// policy.registeredresources.RegisteredResourcesService service. By default, it uses the Connect
// protocol with the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed
// requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or
// connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewRegisteredResourcesServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) RegisteredResourcesServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &registeredResourcesServiceClient{
		createRegisteredResource: connect.NewClient[registeredresources.CreateRegisteredResourceRequest, registeredresources.CreateRegisteredResourceResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceCreateRegisteredResourceProcedure,
			connect.WithSchema(registeredResourcesServiceCreateRegisteredResourceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getRegisteredResource: connect.NewClient[registeredresources.GetRegisteredResourceRequest, registeredresources.GetRegisteredResourceResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceGetRegisteredResourceProcedure,
			connect.WithSchema(registeredResourcesServiceGetRegisteredResourceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listRegisteredResources: connect.NewClient[registeredresources.ListRegisteredResourcesRequest, registeredresources.ListRegisteredResourcesResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceListRegisteredResourcesProcedure,
			connect.WithSchema(registeredResourcesServiceListRegisteredResourcesMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		updateRegisteredResource: connect.NewClient[registeredresources.UpdateRegisteredResourceRequest, registeredresources.UpdateRegisteredResourceResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceUpdateRegisteredResourceProcedure,
			connect.WithSchema(registeredResourcesServiceUpdateRegisteredResourceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		deleteRegisteredResource: connect.NewClient[registeredresources.DeleteRegisteredResourceRequest, registeredresources.DeleteRegisteredResourceResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceDeleteRegisteredResourceProcedure,
			connect.WithSchema(registeredResourcesServiceDeleteRegisteredResourceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		createRegisteredResourceValue: connect.NewClient[registeredresources.CreateRegisteredResourceValueRequest, registeredresources.CreateRegisteredResourceValueResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceCreateRegisteredResourceValueProcedure,
			connect.WithSchema(registeredResourcesServiceCreateRegisteredResourceValueMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getRegisteredResourceValue: connect.NewClient[registeredresources.GetRegisteredResourceValueRequest, registeredresources.GetRegisteredResourceValueResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceGetRegisteredResourceValueProcedure,
			connect.WithSchema(registeredResourcesServiceGetRegisteredResourceValueMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listRegisteredResourceValues: connect.NewClient[registeredresources.ListRegisteredResourceValuesRequest, registeredresources.ListRegisteredResourceValuesResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceListRegisteredResourceValuesProcedure,
			connect.WithSchema(registeredResourcesServiceListRegisteredResourceValuesMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		updateRegisteredResourceValue: connect.NewClient[registeredresources.UpdateRegisteredResourceValueRequest, registeredresources.UpdateRegisteredResourceValueResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceUpdateRegisteredResourceValueProcedure,
			connect.WithSchema(registeredResourcesServiceUpdateRegisteredResourceValueMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		deleteRegisteredResourceValue: connect.NewClient[registeredresources.DeleteRegisteredResourceValueRequest, registeredresources.DeleteRegisteredResourceValueResponse](
			httpClient,
			baseURL+RegisteredResourcesServiceDeleteRegisteredResourceValueProcedure,
			connect.WithSchema(registeredResourcesServiceDeleteRegisteredResourceValueMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// registeredResourcesServiceClient implements RegisteredResourcesServiceClient.
type registeredResourcesServiceClient struct {
	createRegisteredResource      *connect.Client[registeredresources.CreateRegisteredResourceRequest, registeredresources.CreateRegisteredResourceResponse]
	getRegisteredResource         *connect.Client[registeredresources.GetRegisteredResourceRequest, registeredresources.GetRegisteredResourceResponse]
	listRegisteredResources       *connect.Client[registeredresources.ListRegisteredResourcesRequest, registeredresources.ListRegisteredResourcesResponse]
	updateRegisteredResource      *connect.Client[registeredresources.UpdateRegisteredResourceRequest, registeredresources.UpdateRegisteredResourceResponse]
	deleteRegisteredResource      *connect.Client[registeredresources.DeleteRegisteredResourceRequest, registeredresources.DeleteRegisteredResourceResponse]
	createRegisteredResourceValue *connect.Client[registeredresources.CreateRegisteredResourceValueRequest, registeredresources.CreateRegisteredResourceValueResponse]
	getRegisteredResourceValue    *connect.Client[registeredresources.GetRegisteredResourceValueRequest, registeredresources.GetRegisteredResourceValueResponse]
	listRegisteredResourceValues  *connect.Client[registeredresources.ListRegisteredResourceValuesRequest, registeredresources.ListRegisteredResourceValuesResponse]
	updateRegisteredResourceValue *connect.Client[registeredresources.UpdateRegisteredResourceValueRequest, registeredresources.UpdateRegisteredResourceValueResponse]
	deleteRegisteredResourceValue *connect.Client[registeredresources.DeleteRegisteredResourceValueRequest, registeredresources.DeleteRegisteredResourceValueResponse]
}

// CreateRegisteredResource calls
// policy.registeredresources.RegisteredResourcesService.CreateRegisteredResource.
func (c *registeredResourcesServiceClient) CreateRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error) {
	return c.createRegisteredResource.CallUnary(ctx, req)
}

// GetRegisteredResource calls
// policy.registeredresources.RegisteredResourcesService.GetRegisteredResource.
func (c *registeredResourcesServiceClient) GetRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error) {
	return c.getRegisteredResource.CallUnary(ctx, req)
}

// ListRegisteredResources calls
// policy.registeredresources.RegisteredResourcesService.ListRegisteredResources.
func (c *registeredResourcesServiceClient) ListRegisteredResources(ctx context.Context, req *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error) {
	return c.listRegisteredResources.CallUnary(ctx, req)
}

// UpdateRegisteredResource calls
// policy.registeredresources.RegisteredResourcesService.UpdateRegisteredResource.
func (c *registeredResourcesServiceClient) UpdateRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error) {
	return c.updateRegisteredResource.CallUnary(ctx, req)
}

// DeleteRegisteredResource calls
// policy.registeredresources.RegisteredResourcesService.DeleteRegisteredResource.
func (c *registeredResourcesServiceClient) DeleteRegisteredResource(ctx context.Context, req *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error) {
	return c.deleteRegisteredResource.CallUnary(ctx, req)
}

// CreateRegisteredResourceValue calls
// policy.registeredresources.RegisteredResourcesService.CreateRegisteredResourceValue.
func (c *registeredResourcesServiceClient) CreateRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error) {
	return c.createRegisteredResourceValue.CallUnary(ctx, req)
}

// GetRegisteredResourceValue calls
// policy.registeredresources.RegisteredResourcesService.GetRegisteredResourceValue.
func (c *registeredResourcesServiceClient) GetRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error) {
	return c.getRegisteredResourceValue.CallUnary(ctx, req)
}

// ListRegisteredResourceValues calls
// policy.registeredresources.RegisteredResourcesService.ListRegisteredResourceValues.
func (c *registeredResourcesServiceClient) ListRegisteredResourceValues(ctx context.Context, req *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error) {
	return c.listRegisteredResourceValues.CallUnary(ctx, req)
}

// UpdateRegisteredResourceValue calls
// policy.registeredresources.RegisteredResourcesService.UpdateRegisteredResourceValue.
func (c *registeredResourcesServiceClient) UpdateRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error) {
	return c.updateRegisteredResourceValue.CallUnary(ctx, req)
}

// DeleteRegisteredResourceValue calls
// policy.registeredresources.RegisteredResourcesService.DeleteRegisteredResourceValue.
func (c *registeredResourcesServiceClient) DeleteRegisteredResourceValue(ctx context.Context, req *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error) {
	return c.deleteRegisteredResourceValue.CallUnary(ctx, req)
}

// RegisteredResourcesServiceHandler is an implementation of the
// policy.registeredresources.RegisteredResourcesService service.
type RegisteredResourcesServiceHandler interface {
	CreateRegisteredResource(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error)
	GetRegisteredResource(context.Context, *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error)
	ListRegisteredResources(context.Context, *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error)
	UpdateRegisteredResource(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error)
	DeleteRegisteredResource(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error)
	CreateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error)
	GetRegisteredResourceValue(context.Context, *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error)
	ListRegisteredResourceValues(context.Context, *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error)
	UpdateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error)
	DeleteRegisteredResourceValue(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error)
}

// NewRegisteredResourcesServiceHandler builds an HTTP handler from the service implementation. It
// returns the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewRegisteredResourcesServiceHandler(svc RegisteredResourcesServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	registeredResourcesServiceCreateRegisteredResourceHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceCreateRegisteredResourceProcedure,
		svc.CreateRegisteredResource,
		connect.WithSchema(registeredResourcesServiceCreateRegisteredResourceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceGetRegisteredResourceHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceGetRegisteredResourceProcedure,
		svc.GetRegisteredResource,
		connect.WithSchema(registeredResourcesServiceGetRegisteredResourceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceListRegisteredResourcesHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceListRegisteredResourcesProcedure,
		svc.ListRegisteredResources,
		connect.WithSchema(registeredResourcesServiceListRegisteredResourcesMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceUpdateRegisteredResourceHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceUpdateRegisteredResourceProcedure,
		svc.UpdateRegisteredResource,
		connect.WithSchema(registeredResourcesServiceUpdateRegisteredResourceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceDeleteRegisteredResourceHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceDeleteRegisteredResourceProcedure,
		svc.DeleteRegisteredResource,
		connect.WithSchema(registeredResourcesServiceDeleteRegisteredResourceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceCreateRegisteredResourceValueHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceCreateRegisteredResourceValueProcedure,
		svc.CreateRegisteredResourceValue,
		connect.WithSchema(registeredResourcesServiceCreateRegisteredResourceValueMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceGetRegisteredResourceValueHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceGetRegisteredResourceValueProcedure,
		svc.GetRegisteredResourceValue,
		connect.WithSchema(registeredResourcesServiceGetRegisteredResourceValueMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceListRegisteredResourceValuesHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceListRegisteredResourceValuesProcedure,
		svc.ListRegisteredResourceValues,
		connect.WithSchema(registeredResourcesServiceListRegisteredResourceValuesMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceUpdateRegisteredResourceValueHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceUpdateRegisteredResourceValueProcedure,
		svc.UpdateRegisteredResourceValue,
		connect.WithSchema(registeredResourcesServiceUpdateRegisteredResourceValueMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	registeredResourcesServiceDeleteRegisteredResourceValueHandler := connect.NewUnaryHandler(
		RegisteredResourcesServiceDeleteRegisteredResourceValueProcedure,
		svc.DeleteRegisteredResourceValue,
		connect.WithSchema(registeredResourcesServiceDeleteRegisteredResourceValueMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/policy.registeredresources.RegisteredResourcesService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case RegisteredResourcesServiceCreateRegisteredResourceProcedure:
			registeredResourcesServiceCreateRegisteredResourceHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceGetRegisteredResourceProcedure:
			registeredResourcesServiceGetRegisteredResourceHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceListRegisteredResourcesProcedure:
			registeredResourcesServiceListRegisteredResourcesHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceUpdateRegisteredResourceProcedure:
			registeredResourcesServiceUpdateRegisteredResourceHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceDeleteRegisteredResourceProcedure:
			registeredResourcesServiceDeleteRegisteredResourceHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceCreateRegisteredResourceValueProcedure:
			registeredResourcesServiceCreateRegisteredResourceValueHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceGetRegisteredResourceValueProcedure:
			registeredResourcesServiceGetRegisteredResourceValueHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceListRegisteredResourceValuesProcedure:
			registeredResourcesServiceListRegisteredResourceValuesHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceUpdateRegisteredResourceValueProcedure:
			registeredResourcesServiceUpdateRegisteredResourceValueHandler.ServeHTTP(w, r)
		case RegisteredResourcesServiceDeleteRegisteredResourceValueProcedure:
			registeredResourcesServiceDeleteRegisteredResourceValueHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedRegisteredResourcesServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedRegisteredResourcesServiceHandler struct{}

func (UnimplementedRegisteredResourcesServiceHandler) CreateRegisteredResource(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.CreateRegisteredResource is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) GetRegisteredResource(context.Context, *connect.Request[registeredresources.GetRegisteredResourceRequest]) (*connect.Response[registeredresources.GetRegisteredResourceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.GetRegisteredResource is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) ListRegisteredResources(context.Context, *connect.Request[registeredresources.ListRegisteredResourcesRequest]) (*connect.Response[registeredresources.ListRegisteredResourcesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.ListRegisteredResources is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) UpdateRegisteredResource(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.UpdateRegisteredResource is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) DeleteRegisteredResource(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.DeleteRegisteredResource is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) CreateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.CreateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.CreateRegisteredResourceValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.CreateRegisteredResourceValue is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) GetRegisteredResourceValue(context.Context, *connect.Request[registeredresources.GetRegisteredResourceValueRequest]) (*connect.Response[registeredresources.GetRegisteredResourceValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.GetRegisteredResourceValue is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) ListRegisteredResourceValues(context.Context, *connect.Request[registeredresources.ListRegisteredResourceValuesRequest]) (*connect.Response[registeredresources.ListRegisteredResourceValuesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.ListRegisteredResourceValues is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) UpdateRegisteredResourceValue(context.Context, *connect.Request[registeredresources.UpdateRegisteredResourceValueRequest]) (*connect.Response[registeredresources.UpdateRegisteredResourceValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.UpdateRegisteredResourceValue is not implemented"))
}

func (UnimplementedRegisteredResourcesServiceHandler) DeleteRegisteredResourceValue(context.Context, *connect.Request[registeredresources.DeleteRegisteredResourceValueRequest]) (*connect.Response[registeredresources.DeleteRegisteredResourceValueResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.registeredresources.RegisteredResourcesService.DeleteRegisteredResourceValue is not implemented"))
}
