// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: policy/unsafe/unsafe.proto

package unsafe

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	UnsafeService_UpdateNamespace_FullMethodName          = "/policy.unsafe.UnsafeService/UpdateNamespace"
	UnsafeService_ReactivateNamespace_FullMethodName      = "/policy.unsafe.UnsafeService/ReactivateNamespace"
	UnsafeService_DeleteNamespace_FullMethodName          = "/policy.unsafe.UnsafeService/DeleteNamespace"
	UnsafeService_UpdateAttribute_FullMethodName          = "/policy.unsafe.UnsafeService/UpdateAttribute"
	UnsafeService_ReactivateAttribute_FullMethodName      = "/policy.unsafe.UnsafeService/ReactivateAttribute"
	UnsafeService_DeleteAttribute_FullMethodName          = "/policy.unsafe.UnsafeService/DeleteAttribute"
	UnsafeService_UpdateAttributeValue_FullMethodName     = "/policy.unsafe.UnsafeService/UpdateAttributeValue"
	UnsafeService_ReactivateAttributeValue_FullMethodName = "/policy.unsafe.UnsafeService/ReactivateAttributeValue"
	UnsafeService_DeleteAttributeValue_FullMethodName     = "/policy.unsafe.UnsafeService/DeleteAttributeValue"
)

// UnsafeServiceClient is the client API for UnsafeService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UnsafeServiceClient interface {
	// --------------------------------------*
	// Namespace RPCs
	// ---------------------------------------
	UpdateNamespace(ctx context.Context, in *UpdateNamespaceRequest, opts ...grpc.CallOption) (*UpdateNamespaceResponse, error)
	ReactivateNamespace(ctx context.Context, in *ReactivateNamespaceRequest, opts ...grpc.CallOption) (*ReactivateNamespaceResponse, error)
	DeleteNamespace(ctx context.Context, in *DeleteNamespaceRequest, opts ...grpc.CallOption) (*DeleteNamespaceResponse, error)
	// --------------------------------------*
	// Attribute RPCs
	// ---------------------------------------
	UpdateAttribute(ctx context.Context, in *UpdateAttributeRequest, opts ...grpc.CallOption) (*UpdateAttributeResponse, error)
	ReactivateAttribute(ctx context.Context, in *ReactivateAttributeRequest, opts ...grpc.CallOption) (*ReactivateAttributeResponse, error)
	DeleteAttribute(ctx context.Context, in *DeleteAttributeRequest, opts ...grpc.CallOption) (*DeleteAttributeResponse, error)
	// --------------------------------------*
	// Value RPCs
	// ---------------------------------------
	UpdateAttributeValue(ctx context.Context, in *UpdateAttributeValueRequest, opts ...grpc.CallOption) (*UpdateAttributeValueResponse, error)
	ReactivateAttributeValue(ctx context.Context, in *ReactivateAttributeValueRequest, opts ...grpc.CallOption) (*ReactivateAttributeValueResponse, error)
	DeleteAttributeValue(ctx context.Context, in *DeleteAttributeValueRequest, opts ...grpc.CallOption) (*DeleteAttributeValueResponse, error)
}

type unsafeServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUnsafeServiceClient(cc grpc.ClientConnInterface) UnsafeServiceClient {
	return &unsafeServiceClient{cc}
}

func (c *unsafeServiceClient) UpdateNamespace(ctx context.Context, in *UpdateNamespaceRequest, opts ...grpc.CallOption) (*UpdateNamespaceResponse, error) {
	out := new(UpdateNamespaceResponse)
	err := c.cc.Invoke(ctx, UnsafeService_UpdateNamespace_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) ReactivateNamespace(ctx context.Context, in *ReactivateNamespaceRequest, opts ...grpc.CallOption) (*ReactivateNamespaceResponse, error) {
	out := new(ReactivateNamespaceResponse)
	err := c.cc.Invoke(ctx, UnsafeService_ReactivateNamespace_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) DeleteNamespace(ctx context.Context, in *DeleteNamespaceRequest, opts ...grpc.CallOption) (*DeleteNamespaceResponse, error) {
	out := new(DeleteNamespaceResponse)
	err := c.cc.Invoke(ctx, UnsafeService_DeleteNamespace_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) UpdateAttribute(ctx context.Context, in *UpdateAttributeRequest, opts ...grpc.CallOption) (*UpdateAttributeResponse, error) {
	out := new(UpdateAttributeResponse)
	err := c.cc.Invoke(ctx, UnsafeService_UpdateAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) ReactivateAttribute(ctx context.Context, in *ReactivateAttributeRequest, opts ...grpc.CallOption) (*ReactivateAttributeResponse, error) {
	out := new(ReactivateAttributeResponse)
	err := c.cc.Invoke(ctx, UnsafeService_ReactivateAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) DeleteAttribute(ctx context.Context, in *DeleteAttributeRequest, opts ...grpc.CallOption) (*DeleteAttributeResponse, error) {
	out := new(DeleteAttributeResponse)
	err := c.cc.Invoke(ctx, UnsafeService_DeleteAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) UpdateAttributeValue(ctx context.Context, in *UpdateAttributeValueRequest, opts ...grpc.CallOption) (*UpdateAttributeValueResponse, error) {
	out := new(UpdateAttributeValueResponse)
	err := c.cc.Invoke(ctx, UnsafeService_UpdateAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) ReactivateAttributeValue(ctx context.Context, in *ReactivateAttributeValueRequest, opts ...grpc.CallOption) (*ReactivateAttributeValueResponse, error) {
	out := new(ReactivateAttributeValueResponse)
	err := c.cc.Invoke(ctx, UnsafeService_ReactivateAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *unsafeServiceClient) DeleteAttributeValue(ctx context.Context, in *DeleteAttributeValueRequest, opts ...grpc.CallOption) (*DeleteAttributeValueResponse, error) {
	out := new(DeleteAttributeValueResponse)
	err := c.cc.Invoke(ctx, UnsafeService_DeleteAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnsafeServiceServer is the server API for UnsafeService service.
// All implementations must embed UnimplementedUnsafeServiceServer
// for forward compatibility
type UnsafeServiceServer interface {
	// --------------------------------------*
	// Namespace RPCs
	// ---------------------------------------
	UpdateNamespace(context.Context, *UpdateNamespaceRequest) (*UpdateNamespaceResponse, error)
	ReactivateNamespace(context.Context, *ReactivateNamespaceRequest) (*ReactivateNamespaceResponse, error)
	DeleteNamespace(context.Context, *DeleteNamespaceRequest) (*DeleteNamespaceResponse, error)
	// --------------------------------------*
	// Attribute RPCs
	// ---------------------------------------
	UpdateAttribute(context.Context, *UpdateAttributeRequest) (*UpdateAttributeResponse, error)
	ReactivateAttribute(context.Context, *ReactivateAttributeRequest) (*ReactivateAttributeResponse, error)
	DeleteAttribute(context.Context, *DeleteAttributeRequest) (*DeleteAttributeResponse, error)
	// --------------------------------------*
	// Value RPCs
	// ---------------------------------------
	UpdateAttributeValue(context.Context, *UpdateAttributeValueRequest) (*UpdateAttributeValueResponse, error)
	ReactivateAttributeValue(context.Context, *ReactivateAttributeValueRequest) (*ReactivateAttributeValueResponse, error)
	DeleteAttributeValue(context.Context, *DeleteAttributeValueRequest) (*DeleteAttributeValueResponse, error)
	mustEmbedUnimplementedUnsafeServiceServer()
}

// UnimplementedUnsafeServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUnsafeServiceServer struct {
}

func (UnimplementedUnsafeServiceServer) UpdateNamespace(context.Context, *UpdateNamespaceRequest) (*UpdateNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateNamespace not implemented")
}
func (UnimplementedUnsafeServiceServer) ReactivateNamespace(context.Context, *ReactivateNamespaceRequest) (*ReactivateNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReactivateNamespace not implemented")
}
func (UnimplementedUnsafeServiceServer) DeleteNamespace(context.Context, *DeleteNamespaceRequest) (*DeleteNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteNamespace not implemented")
}
func (UnimplementedUnsafeServiceServer) UpdateAttribute(context.Context, *UpdateAttributeRequest) (*UpdateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAttribute not implemented")
}
func (UnimplementedUnsafeServiceServer) ReactivateAttribute(context.Context, *ReactivateAttributeRequest) (*ReactivateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReactivateAttribute not implemented")
}
func (UnimplementedUnsafeServiceServer) DeleteAttribute(context.Context, *DeleteAttributeRequest) (*DeleteAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAttribute not implemented")
}
func (UnimplementedUnsafeServiceServer) UpdateAttributeValue(context.Context, *UpdateAttributeValueRequest) (*UpdateAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAttributeValue not implemented")
}
func (UnimplementedUnsafeServiceServer) ReactivateAttributeValue(context.Context, *ReactivateAttributeValueRequest) (*ReactivateAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReactivateAttributeValue not implemented")
}
func (UnimplementedUnsafeServiceServer) DeleteAttributeValue(context.Context, *DeleteAttributeValueRequest) (*DeleteAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAttributeValue not implemented")
}
func (UnimplementedUnsafeServiceServer) mustEmbedUnimplementedUnsafeServiceServer() {}

// UnsafeUnsafeServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UnsafeServiceServer will
// result in compilation errors.
type UnsafeUnsafeServiceServer interface {
	mustEmbedUnimplementedUnsafeServiceServer()
}

func RegisterUnsafeServiceServer(s grpc.ServiceRegistrar, srv UnsafeServiceServer) {
	s.RegisterService(&UnsafeService_ServiceDesc, srv)
}

func _UnsafeService_UpdateNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).UpdateNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_UpdateNamespace_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).UpdateNamespace(ctx, req.(*UpdateNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_ReactivateNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReactivateNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).ReactivateNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_ReactivateNamespace_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).ReactivateNamespace(ctx, req.(*ReactivateNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_DeleteNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).DeleteNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_DeleteNamespace_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).DeleteNamespace(ctx, req.(*DeleteNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_UpdateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).UpdateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_UpdateAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).UpdateAttribute(ctx, req.(*UpdateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_ReactivateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReactivateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).ReactivateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_ReactivateAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).ReactivateAttribute(ctx, req.(*ReactivateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_DeleteAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).DeleteAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_DeleteAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).DeleteAttribute(ctx, req.(*DeleteAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_UpdateAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).UpdateAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_UpdateAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).UpdateAttributeValue(ctx, req.(*UpdateAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_ReactivateAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReactivateAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).ReactivateAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_ReactivateAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).ReactivateAttributeValue(ctx, req.(*ReactivateAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UnsafeService_DeleteAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UnsafeServiceServer).DeleteAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UnsafeService_DeleteAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UnsafeServiceServer).DeleteAttributeValue(ctx, req.(*DeleteAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// UnsafeService_ServiceDesc is the grpc.ServiceDesc for UnsafeService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var UnsafeService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "policy.unsafe.UnsafeService",
	HandlerType: (*UnsafeServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UpdateNamespace",
			Handler:    _UnsafeService_UpdateNamespace_Handler,
		},
		{
			MethodName: "ReactivateNamespace",
			Handler:    _UnsafeService_ReactivateNamespace_Handler,
		},
		{
			MethodName: "DeleteNamespace",
			Handler:    _UnsafeService_DeleteNamespace_Handler,
		},
		{
			MethodName: "UpdateAttribute",
			Handler:    _UnsafeService_UpdateAttribute_Handler,
		},
		{
			MethodName: "ReactivateAttribute",
			Handler:    _UnsafeService_ReactivateAttribute_Handler,
		},
		{
			MethodName: "DeleteAttribute",
			Handler:    _UnsafeService_DeleteAttribute_Handler,
		},
		{
			MethodName: "UpdateAttributeValue",
			Handler:    _UnsafeService_UpdateAttributeValue_Handler,
		},
		{
			MethodName: "ReactivateAttributeValue",
			Handler:    _UnsafeService_ReactivateAttributeValue_Handler,
		},
		{
			MethodName: "DeleteAttributeValue",
			Handler:    _UnsafeService_DeleteAttributeValue_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "policy/unsafe/unsafe.proto",
}
