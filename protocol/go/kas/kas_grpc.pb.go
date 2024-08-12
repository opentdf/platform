// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: kas/kas.proto

package kas

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AccessService_PublicKey_FullMethodName       = "/kas.AccessService/PublicKey"
	AccessService_LegacyPublicKey_FullMethodName = "/kas.AccessService/LegacyPublicKey"
	AccessService_Rewrap_FullMethodName          = "/kas.AccessService/Rewrap"
)

// AccessServiceClient is the client API for AccessService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AccessServiceClient interface {
	PublicKey(ctx context.Context, in *PublicKeyRequest, opts ...grpc.CallOption) (*PublicKeyResponse, error)
	// buf:lint:ignore RPC_RESPONSE_STANDARD_NAME
	LegacyPublicKey(ctx context.Context, in *LegacyPublicKeyRequest, opts ...grpc.CallOption) (*wrapperspb.StringValue, error)
	Rewrap(ctx context.Context, in *RewrapRequest, opts ...grpc.CallOption) (*RewrapResponse, error)
}

type accessServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAccessServiceClient(cc grpc.ClientConnInterface) AccessServiceClient {
	return &accessServiceClient{cc}
}

func (c *accessServiceClient) PublicKey(ctx context.Context, in *PublicKeyRequest, opts ...grpc.CallOption) (*PublicKeyResponse, error) {
	out := new(PublicKeyResponse)
	err := c.cc.Invoke(ctx, AccessService_PublicKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessServiceClient) LegacyPublicKey(ctx context.Context, in *LegacyPublicKeyRequest, opts ...grpc.CallOption) (*wrapperspb.StringValue, error) {
	out := new(wrapperspb.StringValue)
	err := c.cc.Invoke(ctx, AccessService_LegacyPublicKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accessServiceClient) Rewrap(ctx context.Context, in *RewrapRequest, opts ...grpc.CallOption) (*RewrapResponse, error) {
	out := new(RewrapResponse)
	err := c.cc.Invoke(ctx, AccessService_Rewrap_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccessServiceServer is the server API for AccessService service.
// All implementations must embed UnimplementedAccessServiceServer
// for forward compatibility
type AccessServiceServer interface {
	PublicKey(context.Context, *PublicKeyRequest) (*PublicKeyResponse, error)
	// buf:lint:ignore RPC_RESPONSE_STANDARD_NAME
	LegacyPublicKey(context.Context, *LegacyPublicKeyRequest) (*wrapperspb.StringValue, error)
	Rewrap(context.Context, *RewrapRequest) (*RewrapResponse, error)
	mustEmbedUnimplementedAccessServiceServer()
}

// UnimplementedAccessServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAccessServiceServer struct {
}

func (UnimplementedAccessServiceServer) PublicKey(context.Context, *PublicKeyRequest) (*PublicKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PublicKey not implemented")
}
func (UnimplementedAccessServiceServer) LegacyPublicKey(context.Context, *LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LegacyPublicKey not implemented")
}
func (UnimplementedAccessServiceServer) Rewrap(context.Context, *RewrapRequest) (*RewrapResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Rewrap not implemented")
}
func (UnimplementedAccessServiceServer) mustEmbedUnimplementedAccessServiceServer() {}

// UnsafeAccessServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AccessServiceServer will
// result in compilation errors.
type UnsafeAccessServiceServer interface {
	mustEmbedUnimplementedAccessServiceServer()
}

func RegisterAccessServiceServer(s grpc.ServiceRegistrar, srv AccessServiceServer) {
	s.RegisterService(&AccessService_ServiceDesc, srv)
}

func _AccessService_PublicKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PublicKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessServiceServer).PublicKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessService_PublicKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessServiceServer).PublicKey(ctx, req.(*PublicKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessService_LegacyPublicKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LegacyPublicKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessServiceServer).LegacyPublicKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessService_LegacyPublicKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessServiceServer).LegacyPublicKey(ctx, req.(*LegacyPublicKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AccessService_Rewrap_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RewrapRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccessServiceServer).Rewrap(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AccessService_Rewrap_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccessServiceServer).Rewrap(ctx, req.(*RewrapRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AccessService_ServiceDesc is the grpc.ServiceDesc for AccessService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AccessService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kas.AccessService",
	HandlerType: (*AccessServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PublicKey",
			Handler:    _AccessService_PublicKey_Handler,
		},
		{
			MethodName: "LegacyPublicKey",
			Handler:    _AccessService_LegacyPublicKey_Handler,
		},
		{
			MethodName: "Rewrap",
			Handler:    _AccessService_Rewrap_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kas/kas.proto",
}
