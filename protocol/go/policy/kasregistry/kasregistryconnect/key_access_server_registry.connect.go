// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: policy/kasregistry/key_access_server_registry.proto

package kasregistryconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	kasregistry "github.com/opentdf/platform/protocol/go/policy/kasregistry"
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
	// KeyAccessServerRegistryServiceName is the fully-qualified name of the
	// KeyAccessServerRegistryService service.
	KeyAccessServerRegistryServiceName = "policy.kasregistry.KeyAccessServerRegistryService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// KeyAccessServerRegistryServiceListKeyAccessServersProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's ListKeyAccessServers RPC.
	KeyAccessServerRegistryServiceListKeyAccessServersProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/ListKeyAccessServers"
	// KeyAccessServerRegistryServiceGetKeyAccessServerProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's GetKeyAccessServer RPC.
	KeyAccessServerRegistryServiceGetKeyAccessServerProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/GetKeyAccessServer"
	// KeyAccessServerRegistryServiceCreateKeyAccessServerProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's CreateKeyAccessServer RPC.
	KeyAccessServerRegistryServiceCreateKeyAccessServerProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/CreateKeyAccessServer"
	// KeyAccessServerRegistryServiceUpdateKeyAccessServerProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's UpdateKeyAccessServer RPC.
	KeyAccessServerRegistryServiceUpdateKeyAccessServerProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/UpdateKeyAccessServer"
	// KeyAccessServerRegistryServiceDeleteKeyAccessServerProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's DeleteKeyAccessServer RPC.
	KeyAccessServerRegistryServiceDeleteKeyAccessServerProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/DeleteKeyAccessServer"
	// KeyAccessServerRegistryServiceListKeyAccessServerGrantsProcedure is the fully-qualified name of
	// the KeyAccessServerRegistryService's ListKeyAccessServerGrants RPC.
	KeyAccessServerRegistryServiceListKeyAccessServerGrantsProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/ListKeyAccessServerGrants"
	// KeyAccessServerRegistryServiceCreatePublicKeyProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's CreatePublicKey RPC.
	KeyAccessServerRegistryServiceCreatePublicKeyProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/CreatePublicKey"
	// KeyAccessServerRegistryServiceGetPublicKeyProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's GetPublicKey RPC.
	KeyAccessServerRegistryServiceGetPublicKeyProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/GetPublicKey"
	// KeyAccessServerRegistryServiceListPublicKeysProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's ListPublicKeys RPC.
	KeyAccessServerRegistryServiceListPublicKeysProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/ListPublicKeys"
	// KeyAccessServerRegistryServiceListPublicKeyMappingProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's ListPublicKeyMapping RPC.
	KeyAccessServerRegistryServiceListPublicKeyMappingProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/ListPublicKeyMapping"
	// KeyAccessServerRegistryServiceUpdatePublicKeyProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's UpdatePublicKey RPC.
	KeyAccessServerRegistryServiceUpdatePublicKeyProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/UpdatePublicKey"
	// KeyAccessServerRegistryServiceDeactivatePublicKeyProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's DeactivatePublicKey RPC.
	KeyAccessServerRegistryServiceDeactivatePublicKeyProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/DeactivatePublicKey"
	// KeyAccessServerRegistryServiceActivatePublicKeyProcedure is the fully-qualified name of the
	// KeyAccessServerRegistryService's ActivatePublicKey RPC.
	KeyAccessServerRegistryServiceActivatePublicKeyProcedure = "/policy.kasregistry.KeyAccessServerRegistryService/ActivatePublicKey"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	keyAccessServerRegistryServiceServiceDescriptor                         = kasregistry.File_policy_kasregistry_key_access_server_registry_proto.Services().ByName("KeyAccessServerRegistryService")
	keyAccessServerRegistryServiceListKeyAccessServersMethodDescriptor      = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("ListKeyAccessServers")
	keyAccessServerRegistryServiceGetKeyAccessServerMethodDescriptor        = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("GetKeyAccessServer")
	keyAccessServerRegistryServiceCreateKeyAccessServerMethodDescriptor     = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("CreateKeyAccessServer")
	keyAccessServerRegistryServiceUpdateKeyAccessServerMethodDescriptor     = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("UpdateKeyAccessServer")
	keyAccessServerRegistryServiceDeleteKeyAccessServerMethodDescriptor     = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("DeleteKeyAccessServer")
	keyAccessServerRegistryServiceListKeyAccessServerGrantsMethodDescriptor = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("ListKeyAccessServerGrants")
	keyAccessServerRegistryServiceCreatePublicKeyMethodDescriptor           = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("CreatePublicKey")
	keyAccessServerRegistryServiceGetPublicKeyMethodDescriptor              = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("GetPublicKey")
	keyAccessServerRegistryServiceListPublicKeysMethodDescriptor            = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("ListPublicKeys")
	keyAccessServerRegistryServiceListPublicKeyMappingMethodDescriptor      = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("ListPublicKeyMapping")
	keyAccessServerRegistryServiceUpdatePublicKeyMethodDescriptor           = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("UpdatePublicKey")
	keyAccessServerRegistryServiceDeactivatePublicKeyMethodDescriptor       = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("DeactivatePublicKey")
	keyAccessServerRegistryServiceActivatePublicKeyMethodDescriptor         = keyAccessServerRegistryServiceServiceDescriptor.Methods().ByName("ActivatePublicKey")
)

// KeyAccessServerRegistryServiceClient is a client for the
// policy.kasregistry.KeyAccessServerRegistryService service.
type KeyAccessServerRegistryServiceClient interface {
	ListKeyAccessServers(context.Context, *connect.Request[kasregistry.ListKeyAccessServersRequest]) (*connect.Response[kasregistry.ListKeyAccessServersResponse], error)
	GetKeyAccessServer(context.Context, *connect.Request[kasregistry.GetKeyAccessServerRequest]) (*connect.Response[kasregistry.GetKeyAccessServerResponse], error)
	CreateKeyAccessServer(context.Context, *connect.Request[kasregistry.CreateKeyAccessServerRequest]) (*connect.Response[kasregistry.CreateKeyAccessServerResponse], error)
	UpdateKeyAccessServer(context.Context, *connect.Request[kasregistry.UpdateKeyAccessServerRequest]) (*connect.Response[kasregistry.UpdateKeyAccessServerResponse], error)
	DeleteKeyAccessServer(context.Context, *connect.Request[kasregistry.DeleteKeyAccessServerRequest]) (*connect.Response[kasregistry.DeleteKeyAccessServerResponse], error)
	// Deprecated
	ListKeyAccessServerGrants(context.Context, *connect.Request[kasregistry.ListKeyAccessServerGrantsRequest]) (*connect.Response[kasregistry.ListKeyAccessServerGrantsResponse], error)
	CreatePublicKey(context.Context, *connect.Request[kasregistry.CreatePublicKeyRequest]) (*connect.Response[kasregistry.CreatePublicKeyResponse], error)
	GetPublicKey(context.Context, *connect.Request[kasregistry.GetPublicKeyRequest]) (*connect.Response[kasregistry.GetPublicKeyResponse], error)
	ListPublicKeys(context.Context, *connect.Request[kasregistry.ListPublicKeysRequest]) (*connect.Response[kasregistry.ListPublicKeysResponse], error)
	ListPublicKeyMapping(context.Context, *connect.Request[kasregistry.ListPublicKeyMappingRequest]) (*connect.Response[kasregistry.ListPublicKeyMappingResponse], error)
	UpdatePublicKey(context.Context, *connect.Request[kasregistry.UpdatePublicKeyRequest]) (*connect.Response[kasregistry.UpdatePublicKeyResponse], error)
	DeactivatePublicKey(context.Context, *connect.Request[kasregistry.DeactivatePublicKeyRequest]) (*connect.Response[kasregistry.DeactivatePublicKeyResponse], error)
	ActivatePublicKey(context.Context, *connect.Request[kasregistry.ActivatePublicKeyRequest]) (*connect.Response[kasregistry.ActivatePublicKeyResponse], error)
}

// NewKeyAccessServerRegistryServiceClient constructs a client for the
// policy.kasregistry.KeyAccessServerRegistryService service. By default, it uses the Connect
// protocol with the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed
// requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or
// connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewKeyAccessServerRegistryServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) KeyAccessServerRegistryServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &keyAccessServerRegistryServiceClient{
		listKeyAccessServers: connect.NewClient[kasregistry.ListKeyAccessServersRequest, kasregistry.ListKeyAccessServersResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceListKeyAccessServersProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceListKeyAccessServersMethodDescriptor),
			connect.WithIdempotency(connect.IdempotencyNoSideEffects),
			connect.WithClientOptions(opts...),
		),
		getKeyAccessServer: connect.NewClient[kasregistry.GetKeyAccessServerRequest, kasregistry.GetKeyAccessServerResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceGetKeyAccessServerProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceGetKeyAccessServerMethodDescriptor),
			connect.WithIdempotency(connect.IdempotencyNoSideEffects),
			connect.WithClientOptions(opts...),
		),
		createKeyAccessServer: connect.NewClient[kasregistry.CreateKeyAccessServerRequest, kasregistry.CreateKeyAccessServerResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceCreateKeyAccessServerProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceCreateKeyAccessServerMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		updateKeyAccessServer: connect.NewClient[kasregistry.UpdateKeyAccessServerRequest, kasregistry.UpdateKeyAccessServerResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceUpdateKeyAccessServerProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceUpdateKeyAccessServerMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		deleteKeyAccessServer: connect.NewClient[kasregistry.DeleteKeyAccessServerRequest, kasregistry.DeleteKeyAccessServerResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceDeleteKeyAccessServerProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceDeleteKeyAccessServerMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listKeyAccessServerGrants: connect.NewClient[kasregistry.ListKeyAccessServerGrantsRequest, kasregistry.ListKeyAccessServerGrantsResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceListKeyAccessServerGrantsProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceListKeyAccessServerGrantsMethodDescriptor),
			connect.WithIdempotency(connect.IdempotencyNoSideEffects),
			connect.WithClientOptions(opts...),
		),
		createPublicKey: connect.NewClient[kasregistry.CreatePublicKeyRequest, kasregistry.CreatePublicKeyResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceCreatePublicKeyProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceCreatePublicKeyMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getPublicKey: connect.NewClient[kasregistry.GetPublicKeyRequest, kasregistry.GetPublicKeyResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceGetPublicKeyProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceGetPublicKeyMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listPublicKeys: connect.NewClient[kasregistry.ListPublicKeysRequest, kasregistry.ListPublicKeysResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceListPublicKeysProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceListPublicKeysMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listPublicKeyMapping: connect.NewClient[kasregistry.ListPublicKeyMappingRequest, kasregistry.ListPublicKeyMappingResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceListPublicKeyMappingProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceListPublicKeyMappingMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		updatePublicKey: connect.NewClient[kasregistry.UpdatePublicKeyRequest, kasregistry.UpdatePublicKeyResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceUpdatePublicKeyProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceUpdatePublicKeyMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		deactivatePublicKey: connect.NewClient[kasregistry.DeactivatePublicKeyRequest, kasregistry.DeactivatePublicKeyResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceDeactivatePublicKeyProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceDeactivatePublicKeyMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		activatePublicKey: connect.NewClient[kasregistry.ActivatePublicKeyRequest, kasregistry.ActivatePublicKeyResponse](
			httpClient,
			baseURL+KeyAccessServerRegistryServiceActivatePublicKeyProcedure,
			connect.WithSchema(keyAccessServerRegistryServiceActivatePublicKeyMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// keyAccessServerRegistryServiceClient implements KeyAccessServerRegistryServiceClient.
type keyAccessServerRegistryServiceClient struct {
	listKeyAccessServers      *connect.Client[kasregistry.ListKeyAccessServersRequest, kasregistry.ListKeyAccessServersResponse]
	getKeyAccessServer        *connect.Client[kasregistry.GetKeyAccessServerRequest, kasregistry.GetKeyAccessServerResponse]
	createKeyAccessServer     *connect.Client[kasregistry.CreateKeyAccessServerRequest, kasregistry.CreateKeyAccessServerResponse]
	updateKeyAccessServer     *connect.Client[kasregistry.UpdateKeyAccessServerRequest, kasregistry.UpdateKeyAccessServerResponse]
	deleteKeyAccessServer     *connect.Client[kasregistry.DeleteKeyAccessServerRequest, kasregistry.DeleteKeyAccessServerResponse]
	listKeyAccessServerGrants *connect.Client[kasregistry.ListKeyAccessServerGrantsRequest, kasregistry.ListKeyAccessServerGrantsResponse]
	createPublicKey           *connect.Client[kasregistry.CreatePublicKeyRequest, kasregistry.CreatePublicKeyResponse]
	getPublicKey              *connect.Client[kasregistry.GetPublicKeyRequest, kasregistry.GetPublicKeyResponse]
	listPublicKeys            *connect.Client[kasregistry.ListPublicKeysRequest, kasregistry.ListPublicKeysResponse]
	listPublicKeyMapping      *connect.Client[kasregistry.ListPublicKeyMappingRequest, kasregistry.ListPublicKeyMappingResponse]
	updatePublicKey           *connect.Client[kasregistry.UpdatePublicKeyRequest, kasregistry.UpdatePublicKeyResponse]
	deactivatePublicKey       *connect.Client[kasregistry.DeactivatePublicKeyRequest, kasregistry.DeactivatePublicKeyResponse]
	activatePublicKey         *connect.Client[kasregistry.ActivatePublicKeyRequest, kasregistry.ActivatePublicKeyResponse]
}

// ListKeyAccessServers calls
// policy.kasregistry.KeyAccessServerRegistryService.ListKeyAccessServers.
func (c *keyAccessServerRegistryServiceClient) ListKeyAccessServers(ctx context.Context, req *connect.Request[kasregistry.ListKeyAccessServersRequest]) (*connect.Response[kasregistry.ListKeyAccessServersResponse], error) {
	return c.listKeyAccessServers.CallUnary(ctx, req)
}

// GetKeyAccessServer calls policy.kasregistry.KeyAccessServerRegistryService.GetKeyAccessServer.
func (c *keyAccessServerRegistryServiceClient) GetKeyAccessServer(ctx context.Context, req *connect.Request[kasregistry.GetKeyAccessServerRequest]) (*connect.Response[kasregistry.GetKeyAccessServerResponse], error) {
	return c.getKeyAccessServer.CallUnary(ctx, req)
}

// CreateKeyAccessServer calls
// policy.kasregistry.KeyAccessServerRegistryService.CreateKeyAccessServer.
func (c *keyAccessServerRegistryServiceClient) CreateKeyAccessServer(ctx context.Context, req *connect.Request[kasregistry.CreateKeyAccessServerRequest]) (*connect.Response[kasregistry.CreateKeyAccessServerResponse], error) {
	return c.createKeyAccessServer.CallUnary(ctx, req)
}

// UpdateKeyAccessServer calls
// policy.kasregistry.KeyAccessServerRegistryService.UpdateKeyAccessServer.
func (c *keyAccessServerRegistryServiceClient) UpdateKeyAccessServer(ctx context.Context, req *connect.Request[kasregistry.UpdateKeyAccessServerRequest]) (*connect.Response[kasregistry.UpdateKeyAccessServerResponse], error) {
	return c.updateKeyAccessServer.CallUnary(ctx, req)
}

// DeleteKeyAccessServer calls
// policy.kasregistry.KeyAccessServerRegistryService.DeleteKeyAccessServer.
func (c *keyAccessServerRegistryServiceClient) DeleteKeyAccessServer(ctx context.Context, req *connect.Request[kasregistry.DeleteKeyAccessServerRequest]) (*connect.Response[kasregistry.DeleteKeyAccessServerResponse], error) {
	return c.deleteKeyAccessServer.CallUnary(ctx, req)
}

// ListKeyAccessServerGrants calls
// policy.kasregistry.KeyAccessServerRegistryService.ListKeyAccessServerGrants.
func (c *keyAccessServerRegistryServiceClient) ListKeyAccessServerGrants(ctx context.Context, req *connect.Request[kasregistry.ListKeyAccessServerGrantsRequest]) (*connect.Response[kasregistry.ListKeyAccessServerGrantsResponse], error) {
	return c.listKeyAccessServerGrants.CallUnary(ctx, req)
}

// CreatePublicKey calls policy.kasregistry.KeyAccessServerRegistryService.CreatePublicKey.
func (c *keyAccessServerRegistryServiceClient) CreatePublicKey(ctx context.Context, req *connect.Request[kasregistry.CreatePublicKeyRequest]) (*connect.Response[kasregistry.CreatePublicKeyResponse], error) {
	return c.createPublicKey.CallUnary(ctx, req)
}

// GetPublicKey calls policy.kasregistry.KeyAccessServerRegistryService.GetPublicKey.
func (c *keyAccessServerRegistryServiceClient) GetPublicKey(ctx context.Context, req *connect.Request[kasregistry.GetPublicKeyRequest]) (*connect.Response[kasregistry.GetPublicKeyResponse], error) {
	return c.getPublicKey.CallUnary(ctx, req)
}

// ListPublicKeys calls policy.kasregistry.KeyAccessServerRegistryService.ListPublicKeys.
func (c *keyAccessServerRegistryServiceClient) ListPublicKeys(ctx context.Context, req *connect.Request[kasregistry.ListPublicKeysRequest]) (*connect.Response[kasregistry.ListPublicKeysResponse], error) {
	return c.listPublicKeys.CallUnary(ctx, req)
}

// ListPublicKeyMapping calls
// policy.kasregistry.KeyAccessServerRegistryService.ListPublicKeyMapping.
func (c *keyAccessServerRegistryServiceClient) ListPublicKeyMapping(ctx context.Context, req *connect.Request[kasregistry.ListPublicKeyMappingRequest]) (*connect.Response[kasregistry.ListPublicKeyMappingResponse], error) {
	return c.listPublicKeyMapping.CallUnary(ctx, req)
}

// UpdatePublicKey calls policy.kasregistry.KeyAccessServerRegistryService.UpdatePublicKey.
func (c *keyAccessServerRegistryServiceClient) UpdatePublicKey(ctx context.Context, req *connect.Request[kasregistry.UpdatePublicKeyRequest]) (*connect.Response[kasregistry.UpdatePublicKeyResponse], error) {
	return c.updatePublicKey.CallUnary(ctx, req)
}

// DeactivatePublicKey calls policy.kasregistry.KeyAccessServerRegistryService.DeactivatePublicKey.
func (c *keyAccessServerRegistryServiceClient) DeactivatePublicKey(ctx context.Context, req *connect.Request[kasregistry.DeactivatePublicKeyRequest]) (*connect.Response[kasregistry.DeactivatePublicKeyResponse], error) {
	return c.deactivatePublicKey.CallUnary(ctx, req)
}

// ActivatePublicKey calls policy.kasregistry.KeyAccessServerRegistryService.ActivatePublicKey.
func (c *keyAccessServerRegistryServiceClient) ActivatePublicKey(ctx context.Context, req *connect.Request[kasregistry.ActivatePublicKeyRequest]) (*connect.Response[kasregistry.ActivatePublicKeyResponse], error) {
	return c.activatePublicKey.CallUnary(ctx, req)
}

// KeyAccessServerRegistryServiceHandler is an implementation of the
// policy.kasregistry.KeyAccessServerRegistryService service.
type KeyAccessServerRegistryServiceHandler interface {
	ListKeyAccessServers(context.Context, *connect.Request[kasregistry.ListKeyAccessServersRequest]) (*connect.Response[kasregistry.ListKeyAccessServersResponse], error)
	GetKeyAccessServer(context.Context, *connect.Request[kasregistry.GetKeyAccessServerRequest]) (*connect.Response[kasregistry.GetKeyAccessServerResponse], error)
	CreateKeyAccessServer(context.Context, *connect.Request[kasregistry.CreateKeyAccessServerRequest]) (*connect.Response[kasregistry.CreateKeyAccessServerResponse], error)
	UpdateKeyAccessServer(context.Context, *connect.Request[kasregistry.UpdateKeyAccessServerRequest]) (*connect.Response[kasregistry.UpdateKeyAccessServerResponse], error)
	DeleteKeyAccessServer(context.Context, *connect.Request[kasregistry.DeleteKeyAccessServerRequest]) (*connect.Response[kasregistry.DeleteKeyAccessServerResponse], error)
	// Deprecated
	ListKeyAccessServerGrants(context.Context, *connect.Request[kasregistry.ListKeyAccessServerGrantsRequest]) (*connect.Response[kasregistry.ListKeyAccessServerGrantsResponse], error)
	CreatePublicKey(context.Context, *connect.Request[kasregistry.CreatePublicKeyRequest]) (*connect.Response[kasregistry.CreatePublicKeyResponse], error)
	GetPublicKey(context.Context, *connect.Request[kasregistry.GetPublicKeyRequest]) (*connect.Response[kasregistry.GetPublicKeyResponse], error)
	ListPublicKeys(context.Context, *connect.Request[kasregistry.ListPublicKeysRequest]) (*connect.Response[kasregistry.ListPublicKeysResponse], error)
	ListPublicKeyMapping(context.Context, *connect.Request[kasregistry.ListPublicKeyMappingRequest]) (*connect.Response[kasregistry.ListPublicKeyMappingResponse], error)
	UpdatePublicKey(context.Context, *connect.Request[kasregistry.UpdatePublicKeyRequest]) (*connect.Response[kasregistry.UpdatePublicKeyResponse], error)
	DeactivatePublicKey(context.Context, *connect.Request[kasregistry.DeactivatePublicKeyRequest]) (*connect.Response[kasregistry.DeactivatePublicKeyResponse], error)
	ActivatePublicKey(context.Context, *connect.Request[kasregistry.ActivatePublicKeyRequest]) (*connect.Response[kasregistry.ActivatePublicKeyResponse], error)
}

// NewKeyAccessServerRegistryServiceHandler builds an HTTP handler from the service implementation.
// It returns the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewKeyAccessServerRegistryServiceHandler(svc KeyAccessServerRegistryServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	keyAccessServerRegistryServiceListKeyAccessServersHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceListKeyAccessServersProcedure,
		svc.ListKeyAccessServers,
		connect.WithSchema(keyAccessServerRegistryServiceListKeyAccessServersMethodDescriptor),
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceGetKeyAccessServerHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceGetKeyAccessServerProcedure,
		svc.GetKeyAccessServer,
		connect.WithSchema(keyAccessServerRegistryServiceGetKeyAccessServerMethodDescriptor),
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceCreateKeyAccessServerHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceCreateKeyAccessServerProcedure,
		svc.CreateKeyAccessServer,
		connect.WithSchema(keyAccessServerRegistryServiceCreateKeyAccessServerMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceUpdateKeyAccessServerHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceUpdateKeyAccessServerProcedure,
		svc.UpdateKeyAccessServer,
		connect.WithSchema(keyAccessServerRegistryServiceUpdateKeyAccessServerMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceDeleteKeyAccessServerHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceDeleteKeyAccessServerProcedure,
		svc.DeleteKeyAccessServer,
		connect.WithSchema(keyAccessServerRegistryServiceDeleteKeyAccessServerMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceListKeyAccessServerGrantsHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceListKeyAccessServerGrantsProcedure,
		svc.ListKeyAccessServerGrants,
		connect.WithSchema(keyAccessServerRegistryServiceListKeyAccessServerGrantsMethodDescriptor),
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceCreatePublicKeyHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceCreatePublicKeyProcedure,
		svc.CreatePublicKey,
		connect.WithSchema(keyAccessServerRegistryServiceCreatePublicKeyMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceGetPublicKeyHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceGetPublicKeyProcedure,
		svc.GetPublicKey,
		connect.WithSchema(keyAccessServerRegistryServiceGetPublicKeyMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceListPublicKeysHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceListPublicKeysProcedure,
		svc.ListPublicKeys,
		connect.WithSchema(keyAccessServerRegistryServiceListPublicKeysMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceListPublicKeyMappingHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceListPublicKeyMappingProcedure,
		svc.ListPublicKeyMapping,
		connect.WithSchema(keyAccessServerRegistryServiceListPublicKeyMappingMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceUpdatePublicKeyHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceUpdatePublicKeyProcedure,
		svc.UpdatePublicKey,
		connect.WithSchema(keyAccessServerRegistryServiceUpdatePublicKeyMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceDeactivatePublicKeyHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceDeactivatePublicKeyProcedure,
		svc.DeactivatePublicKey,
		connect.WithSchema(keyAccessServerRegistryServiceDeactivatePublicKeyMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	keyAccessServerRegistryServiceActivatePublicKeyHandler := connect.NewUnaryHandler(
		KeyAccessServerRegistryServiceActivatePublicKeyProcedure,
		svc.ActivatePublicKey,
		connect.WithSchema(keyAccessServerRegistryServiceActivatePublicKeyMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/policy.kasregistry.KeyAccessServerRegistryService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case KeyAccessServerRegistryServiceListKeyAccessServersProcedure:
			keyAccessServerRegistryServiceListKeyAccessServersHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceGetKeyAccessServerProcedure:
			keyAccessServerRegistryServiceGetKeyAccessServerHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceCreateKeyAccessServerProcedure:
			keyAccessServerRegistryServiceCreateKeyAccessServerHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceUpdateKeyAccessServerProcedure:
			keyAccessServerRegistryServiceUpdateKeyAccessServerHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceDeleteKeyAccessServerProcedure:
			keyAccessServerRegistryServiceDeleteKeyAccessServerHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceListKeyAccessServerGrantsProcedure:
			keyAccessServerRegistryServiceListKeyAccessServerGrantsHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceCreatePublicKeyProcedure:
			keyAccessServerRegistryServiceCreatePublicKeyHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceGetPublicKeyProcedure:
			keyAccessServerRegistryServiceGetPublicKeyHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceListPublicKeysProcedure:
			keyAccessServerRegistryServiceListPublicKeysHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceListPublicKeyMappingProcedure:
			keyAccessServerRegistryServiceListPublicKeyMappingHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceUpdatePublicKeyProcedure:
			keyAccessServerRegistryServiceUpdatePublicKeyHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceDeactivatePublicKeyProcedure:
			keyAccessServerRegistryServiceDeactivatePublicKeyHandler.ServeHTTP(w, r)
		case KeyAccessServerRegistryServiceActivatePublicKeyProcedure:
			keyAccessServerRegistryServiceActivatePublicKeyHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedKeyAccessServerRegistryServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedKeyAccessServerRegistryServiceHandler struct{}

func (UnimplementedKeyAccessServerRegistryServiceHandler) ListKeyAccessServers(context.Context, *connect.Request[kasregistry.ListKeyAccessServersRequest]) (*connect.Response[kasregistry.ListKeyAccessServersResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.ListKeyAccessServers is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) GetKeyAccessServer(context.Context, *connect.Request[kasregistry.GetKeyAccessServerRequest]) (*connect.Response[kasregistry.GetKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.GetKeyAccessServer is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) CreateKeyAccessServer(context.Context, *connect.Request[kasregistry.CreateKeyAccessServerRequest]) (*connect.Response[kasregistry.CreateKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.CreateKeyAccessServer is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) UpdateKeyAccessServer(context.Context, *connect.Request[kasregistry.UpdateKeyAccessServerRequest]) (*connect.Response[kasregistry.UpdateKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.UpdateKeyAccessServer is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) DeleteKeyAccessServer(context.Context, *connect.Request[kasregistry.DeleteKeyAccessServerRequest]) (*connect.Response[kasregistry.DeleteKeyAccessServerResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.DeleteKeyAccessServer is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) ListKeyAccessServerGrants(context.Context, *connect.Request[kasregistry.ListKeyAccessServerGrantsRequest]) (*connect.Response[kasregistry.ListKeyAccessServerGrantsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.ListKeyAccessServerGrants is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) CreatePublicKey(context.Context, *connect.Request[kasregistry.CreatePublicKeyRequest]) (*connect.Response[kasregistry.CreatePublicKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.CreatePublicKey is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) GetPublicKey(context.Context, *connect.Request[kasregistry.GetPublicKeyRequest]) (*connect.Response[kasregistry.GetPublicKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.GetPublicKey is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) ListPublicKeys(context.Context, *connect.Request[kasregistry.ListPublicKeysRequest]) (*connect.Response[kasregistry.ListPublicKeysResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.ListPublicKeys is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) ListPublicKeyMapping(context.Context, *connect.Request[kasregistry.ListPublicKeyMappingRequest]) (*connect.Response[kasregistry.ListPublicKeyMappingResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.ListPublicKeyMapping is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) UpdatePublicKey(context.Context, *connect.Request[kasregistry.UpdatePublicKeyRequest]) (*connect.Response[kasregistry.UpdatePublicKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.UpdatePublicKey is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) DeactivatePublicKey(context.Context, *connect.Request[kasregistry.DeactivatePublicKeyRequest]) (*connect.Response[kasregistry.DeactivatePublicKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.DeactivatePublicKey is not implemented"))
}

func (UnimplementedKeyAccessServerRegistryServiceHandler) ActivatePublicKey(context.Context, *connect.Request[kasregistry.ActivatePublicKeyRequest]) (*connect.Response[kasregistry.ActivatePublicKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("policy.kasregistry.KeyAccessServerRegistryService.ActivatePublicKey is not implemented"))
}
