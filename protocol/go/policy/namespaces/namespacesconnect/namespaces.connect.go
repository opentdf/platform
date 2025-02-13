// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: policy/namespaces/namespaces.proto

package namespacesconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	namespaces "github.com/opentdf/platform/protocol/go/policy/namespaces"
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
	// NamespaceServiceName is the fully-qualified name of the NamespaceService service.
	NamespaceServiceName = "policy.namespaces.NamespaceService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// NamespaceServiceGetNamespaceProcedure is the fully-qualified name of the NamespaceService's
	// GetNamespace RPC.
	NamespaceServiceGetNamespaceProcedure = "/policy.namespaces.NamespaceService/GetNamespace"
	// NamespaceServiceListNamespacesProcedure is the fully-qualified name of the NamespaceService's
	// ListNamespaces RPC.
	NamespaceServiceListNamespacesProcedure = "/policy.namespaces.NamespaceService/ListNamespaces"
	// NamespaceServiceCreateNamespaceProcedure is the fully-qualified name of the NamespaceService's
	// CreateNamespace RPC.
	NamespaceServiceCreateNamespaceProcedure = "/policy.namespaces.NamespaceService/CreateNamespace"
	// NamespaceServiceUpdateNamespaceProcedure is the fully-qualified name of the NamespaceService's
	// UpdateNamespace RPC.
	NamespaceServiceUpdateNamespaceProcedure = "/policy.namespaces.NamespaceService/UpdateNamespace"
	// NamespaceServiceDeactivateNamespaceProcedure is the fully-qualified name of the
	// NamespaceService's DeactivateNamespace RPC.
	NamespaceServiceDeactivateNamespaceProcedure = "/policy.namespaces.NamespaceService/DeactivateNamespace"
	// NamespaceServiceAssignKeyAccessServerToNamespaceProcedure is the fully-qualified name of the
	// NamespaceService's AssignKeyAccessServerToNamespace RPC.
	NamespaceServiceAssignKeyAccessServerToNamespaceProcedure = "/policy.namespaces.NamespaceService/AssignKeyAccessServerToNamespace"
	// NamespaceServiceRemoveKeyAccessServerFromNamespaceProcedure is the fully-qualified name of the
	// NamespaceService's RemoveKeyAccessServerFromNamespace RPC.
	NamespaceServiceRemoveKeyAccessServerFromNamespaceProcedure = "/policy.namespaces.NamespaceService/RemoveKeyAccessServerFromNamespace"
	// NamespaceServiceAssignKeyToNamespaceProcedure is the fully-qualified name of the
	// NamespaceService's AssignKeyToNamespace RPC.
	NamespaceServiceAssignKeyToNamespaceProcedure = "/policy.namespaces.NamespaceService/AssignKeyToNamespace"
	// NamespaceServiceRemoveKeyFromNamespaceProcedure is the fully-qualified name of the
	// NamespaceService's RemoveKeyFromNamespace RPC.
	NamespaceServiceRemoveKeyFromNamespaceProcedure = "/policy.namespaces.NamespaceService/RemoveKeyFromNamespace"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	namespaceServiceServiceDescriptor                                  = namespaces.File_policy_namespaces_namespaces_proto.Services().ByName("NamespaceService")
	namespaceServiceGetNamespaceMethodDescriptor                       = namespaceServiceServiceDescriptor.Methods().ByName("GetNamespace")
	namespaceServiceListNamespacesMethodDescriptor                     = namespaceServiceServiceDescriptor.Methods().ByName("ListNamespaces")
	namespaceServiceCreateNamespaceMethodDescriptor                    = namespaceServiceServiceDescriptor.Methods().ByName("CreateNamespace")
	namespaceServiceUpdateNamespaceMethodDescriptor                    = namespaceServiceServiceDescriptor.Methods().ByName("UpdateNamespace")
	namespaceServiceDeactivateNamespaceMethodDescriptor                = namespaceServiceServiceDescriptor.Methods().ByName("DeactivateNamespace")
	namespaceServiceAssignKeyAccessServerToNamespaceMethodDescriptor   = namespaceServiceServiceDescriptor.Methods().ByName("AssignKeyAccessServerToNamespace")
	namespaceServiceRemoveKeyAccessServerFromNamespaceMethodDescriptor = namespaceServiceServiceDescriptor.Methods().ByName("RemoveKeyAccessServerFromNamespace")
	namespaceServiceAssignKeyToNamespaceMethodDescriptor               = namespaceServiceServiceDescriptor.Methods().ByName("AssignKeyToNamespace")
	namespaceServiceRemoveKeyFromNamespaceMethodDescriptor             = namespaceServiceServiceDescriptor.Methods().ByName("RemoveKeyFromNamespace")
)

// NamespaceServiceClient is a client for the policy.namespaces.NamespaceService service.
type NamespaceServiceClient interface {
	GetNamespace(context.Context, *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error)
	ListNamespaces(context.Context, *connect.Request[namespaces.ListNamespacesRequest]) (*connect.Response[namespaces.ListNamespacesResponse], error)
	CreateNamespace(context.Context, *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error)
	UpdateNamespace(context.Context, *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error)
	DeactivateNamespace(context.Context, *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error)
	// --------------------------------------*
	// Namespace <> Key Access Server RPCs
	// ---------------------------------------
	AssignKeyAccessServerToNamespace(context.Context, *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error)
	RemoveKeyAccessServerFromNamespace(context.Context, *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error)
	// --------------------------------------*
	// Namespace <> Key RPCs
	// ---------------------------------------
	AssignKeyToNamespace(context.Context, *connect.Request[namespaces.AssignKeyToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyToNamespaceResponse], error)
	RemoveKeyFromNamespace(context.Context, *connect.Request[namespaces.RemoveKeyFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyFromNamespaceResponse], error)
}

// NewNamespaceServiceClient constructs a client for the policy.namespaces.NamespaceService service.
// By default, it uses the Connect protocol with the binary Protobuf Codec, asks for gzipped
// responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the
// connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewNamespaceServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) NamespaceServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &namespaceServiceClient{
		getNamespace: connect.NewClient[namespaces.GetNamespaceRequest, namespaces.GetNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceGetNamespaceProcedure,
			connect.WithSchema(namespaceServiceGetNamespaceMethodDescriptor),
			connect.WithIdempotency(connect.IdempotencyNoSideEffects),
			connect.WithClientOptions(opts...),
		),
		listNamespaces: connect.NewClient[namespaces.ListNamespacesRequest, namespaces.ListNamespacesResponse](
			httpClient,
			baseURL+NamespaceServiceListNamespacesProcedure,
			connect.WithSchema(namespaceServiceListNamespacesMethodDescriptor),
			connect.WithIdempotency(connect.IdempotencyNoSideEffects),
			connect.WithClientOptions(opts...),
		),
		createNamespace: connect.NewClient[namespaces.CreateNamespaceRequest, namespaces.CreateNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceCreateNamespaceProcedure,
			connect.WithSchema(namespaceServiceCreateNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		updateNamespace: connect.NewClient[namespaces.UpdateNamespaceRequest, namespaces.UpdateNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceUpdateNamespaceProcedure,
			connect.WithSchema(namespaceServiceUpdateNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		deactivateNamespace: connect.NewClient[namespaces.DeactivateNamespaceRequest, namespaces.DeactivateNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceDeactivateNamespaceProcedure,
			connect.WithSchema(namespaceServiceDeactivateNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		assignKeyAccessServerToNamespace: connect.NewClient[namespaces.AssignKeyAccessServerToNamespaceRequest, namespaces.AssignKeyAccessServerToNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceAssignKeyAccessServerToNamespaceProcedure,
			connect.WithSchema(namespaceServiceAssignKeyAccessServerToNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		removeKeyAccessServerFromNamespace: connect.NewClient[namespaces.RemoveKeyAccessServerFromNamespaceRequest, namespaces.RemoveKeyAccessServerFromNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceRemoveKeyAccessServerFromNamespaceProcedure,
			connect.WithSchema(namespaceServiceRemoveKeyAccessServerFromNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		assignKeyToNamespace: connect.NewClient[namespaces.AssignKeyToNamespaceRequest, namespaces.AssignKeyToNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceAssignKeyToNamespaceProcedure,
			connect.WithSchema(namespaceServiceAssignKeyToNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		removeKeyFromNamespace: connect.NewClient[namespaces.RemoveKeyFromNamespaceRequest, namespaces.RemoveKeyFromNamespaceResponse](
			httpClient,
			baseURL+NamespaceServiceRemoveKeyFromNamespaceProcedure,
			connect.WithSchema(namespaceServiceRemoveKeyFromNamespaceMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// namespaceServiceClient implements NamespaceServiceClient.
type namespaceServiceClient struct {
	getNamespace                       *connect.Client[namespaces.GetNamespaceRequest, namespaces.GetNamespaceResponse]
	listNamespaces                     *connect.Client[namespaces.ListNamespacesRequest, namespaces.ListNamespacesResponse]
	createNamespace                    *connect.Client[namespaces.CreateNamespaceRequest, namespaces.CreateNamespaceResponse]
	updateNamespace                    *connect.Client[namespaces.UpdateNamespaceRequest, namespaces.UpdateNamespaceResponse]
	deactivateNamespace                *connect.Client[namespaces.DeactivateNamespaceRequest, namespaces.DeactivateNamespaceResponse]
	assignKeyAccessServerToNamespace   *connect.Client[namespaces.AssignKeyAccessServerToNamespaceRequest, namespaces.AssignKeyAccessServerToNamespaceResponse]
	removeKeyAccessServerFromNamespace *connect.Client[namespaces.RemoveKeyAccessServerFromNamespaceRequest, namespaces.RemoveKeyAccessServerFromNamespaceResponse]
	assignKeyToNamespace               *connect.Client[namespaces.AssignKeyToNamespaceRequest, namespaces.AssignKeyToNamespaceResponse]
	removeKeyFromNamespace             *connect.Client[namespaces.RemoveKeyFromNamespaceRequest, namespaces.RemoveKeyFromNamespaceResponse]
}

// GetNamespace calls policy.namespaces.NamespaceService.GetNamespace.
func (c *namespaceServiceClient) GetNamespace(ctx context.Context, req *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error) {
	return c.getNamespace.CallUnary(ctx, req)
}

// ListNamespaces calls policy.namespaces.NamespaceService.ListNamespaces.
func (c *namespaceServiceClient) ListNamespaces(ctx context.Context, req *connect.Request[namespaces.ListNamespacesRequest]) (*connect.Response[namespaces.ListNamespacesResponse], error) {
	return c.listNamespaces.CallUnary(ctx, req)
}

// CreateNamespace calls policy.namespaces.NamespaceService.CreateNamespace.
func (c *namespaceServiceClient) CreateNamespace(ctx context.Context, req *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error) {
	return c.createNamespace.CallUnary(ctx, req)
}

// UpdateNamespace calls policy.namespaces.NamespaceService.UpdateNamespace.
func (c *namespaceServiceClient) UpdateNamespace(ctx context.Context, req *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error) {
	return c.updateNamespace.CallUnary(ctx, req)
}

// DeactivateNamespace calls policy.namespaces.NamespaceService.DeactivateNamespace.
func (c *namespaceServiceClient) DeactivateNamespace(ctx context.Context, req *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error) {
	return c.deactivateNamespace.CallUnary(ctx, req)
}

// AssignKeyAccessServerToNamespace calls
// policy.namespaces.NamespaceService.AssignKeyAccessServerToNamespace.
func (c *namespaceServiceClient) AssignKeyAccessServerToNamespace(ctx context.Context, req *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error) {
	return c.assignKeyAccessServerToNamespace.CallUnary(ctx, req)
}

// RemoveKeyAccessServerFromNamespace calls
// policy.namespaces.NamespaceService.RemoveKeyAccessServerFromNamespace.
func (c *namespaceServiceClient) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error) {
	return c.removeKeyAccessServerFromNamespace.CallUnary(ctx, req)
}

// AssignKeyToNamespace calls policy.namespaces.NamespaceService.AssignKeyToNamespace.
func (c *namespaceServiceClient) AssignKeyToNamespace(ctx context.Context, req *connect.Request[namespaces.AssignKeyToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyToNamespaceResponse], error) {
	return c.assignKeyToNamespace.CallUnary(ctx, req)
}

// RemoveKeyFromNamespace calls policy.namespaces.NamespaceService.RemoveKeyFromNamespace.
func (c *namespaceServiceClient) RemoveKeyFromNamespace(ctx context.Context, req *connect.Request[namespaces.RemoveKeyFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyFromNamespaceResponse], error) {
	return c.removeKeyFromNamespace.CallUnary(ctx, req)
}

// NamespaceServiceHandler is an implementation of the policy.namespaces.NamespaceService service.
type NamespaceServiceHandler interface {
	GetNamespace(context.Context, *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error)
	ListNamespaces(context.Context, *connect.Request[namespaces.ListNamespacesRequest]) (*connect.Response[namespaces.ListNamespacesResponse], error)
	CreateNamespace(context.Context, *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error)
	UpdateNamespace(context.Context, *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error)
	DeactivateNamespace(context.Context, *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error)
	// --------------------------------------*
	// Namespace <> Key Access Server RPCs
	// ---------------------------------------
	AssignKeyAccessServerToNamespace(context.Context, *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error)
	RemoveKeyAccessServerFromNamespace(context.Context, *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error)
	// --------------------------------------*
	// Namespace <> Key RPCs
	// ---------------------------------------
	AssignKeyToNamespace(context.Context, *connect.Request[namespaces.AssignKeyToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyToNamespaceResponse], error)
	RemoveKeyFromNamespace(context.Context, *connect.Request[namespaces.RemoveKeyFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyFromNamespaceResponse], error)
}

// NewNamespaceServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewNamespaceServiceHandler(svc NamespaceServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	namespaceServiceGetNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceGetNamespaceProcedure,
		svc.GetNamespace,
		connect.WithSchema(namespaceServiceGetNamespaceMethodDescriptor),
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceListNamespacesHandler := connect.NewUnaryHandler(
		NamespaceServiceListNamespacesProcedure,
		svc.ListNamespaces,
		connect.WithSchema(namespaceServiceListNamespacesMethodDescriptor),
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceCreateNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceCreateNamespaceProcedure,
		svc.CreateNamespace,
		connect.WithSchema(namespaceServiceCreateNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceUpdateNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceUpdateNamespaceProcedure,
		svc.UpdateNamespace,
		connect.WithSchema(namespaceServiceUpdateNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceDeactivateNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceDeactivateNamespaceProcedure,
		svc.DeactivateNamespace,
		connect.WithSchema(namespaceServiceDeactivateNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceAssignKeyAccessServerToNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceAssignKeyAccessServerToNamespaceProcedure,
		svc.AssignKeyAccessServerToNamespace,
		connect.WithSchema(namespaceServiceAssignKeyAccessServerToNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceRemoveKeyAccessServerFromNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceRemoveKeyAccessServerFromNamespaceProcedure,
		svc.RemoveKeyAccessServerFromNamespace,
		connect.WithSchema(namespaceServiceRemoveKeyAccessServerFromNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceAssignKeyToNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceAssignKeyToNamespaceProcedure,
		svc.AssignKeyToNamespace,
		connect.WithSchema(namespaceServiceAssignKeyToNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	namespaceServiceRemoveKeyFromNamespaceHandler := connect.NewUnaryHandler(
		NamespaceServiceRemoveKeyFromNamespaceProcedure,
		svc.RemoveKeyFromNamespace,
		connect.WithSchema(namespaceServiceRemoveKeyFromNamespaceMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/policy.namespaces.NamespaceService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case NamespaceServiceGetNamespaceProcedure:
			namespaceServiceGetNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceListNamespacesProcedure:
			namespaceServiceListNamespacesHandler.ServeHTTP(w, r)
		case NamespaceServiceCreateNamespaceProcedure:
			namespaceServiceCreateNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceUpdateNamespaceProcedure:
			namespaceServiceUpdateNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceDeactivateNamespaceProcedure:
			namespaceServiceDeactivateNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceAssignKeyAccessServerToNamespaceProcedure:
			namespaceServiceAssignKeyAccessServerToNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceRemoveKeyAccessServerFromNamespaceProcedure:
			namespaceServiceRemoveKeyAccessServerFromNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceAssignKeyToNamespaceProcedure:
			namespaceServiceAssignKeyToNamespaceHandler.ServeHTTP(w, r)
		case NamespaceServiceRemoveKeyFromNamespaceProcedure:
			namespaceServiceRemoveKeyFromNamespaceHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedNamespaceServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedNamespaceServiceHandler struct{}

func (UnimplementedNamespaceServiceHandler) GetNamespace(context.Context, *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.GetNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) ListNamespaces(context.Context, *connect.Request[namespaces.ListNamespacesRequest]) (*connect.Response[namespaces.ListNamespacesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.ListNamespaces is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) CreateNamespace(context.Context, *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.CreateNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) UpdateNamespace(context.Context, *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.UpdateNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) DeactivateNamespace(context.Context, *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.DeactivateNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) AssignKeyAccessServerToNamespace(context.Context, *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.AssignKeyAccessServerToNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) RemoveKeyAccessServerFromNamespace(context.Context, *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.RemoveKeyAccessServerFromNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) AssignKeyToNamespace(context.Context, *connect.Request[namespaces.AssignKeyToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyToNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.AssignKeyToNamespace is not implemented"))
}

func (UnimplementedNamespaceServiceHandler) RemoveKeyFromNamespace(context.Context, *connect.Request[namespaces.RemoveKeyFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyFromNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.namespaces.NamespaceService.RemoveKeyFromNamespace is not implemented"))
}
