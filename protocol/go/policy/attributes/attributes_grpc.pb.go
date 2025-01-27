// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: policy/attributes/attributes.proto

package attributes

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
	AttributesService_ListAttributes_FullMethodName                     = "/policy.attributes.AttributesService/ListAttributes"
	AttributesService_ListAttributeValues_FullMethodName                = "/policy.attributes.AttributesService/ListAttributeValues"
	AttributesService_GetAttribute_FullMethodName                       = "/policy.attributes.AttributesService/GetAttribute"
	AttributesService_GetAttributeValuesByFqns_FullMethodName           = "/policy.attributes.AttributesService/GetAttributeValuesByFqns"
	AttributesService_CreateAttribute_FullMethodName                    = "/policy.attributes.AttributesService/CreateAttribute"
	AttributesService_UpdateAttribute_FullMethodName                    = "/policy.attributes.AttributesService/UpdateAttribute"
	AttributesService_DeactivateAttribute_FullMethodName                = "/policy.attributes.AttributesService/DeactivateAttribute"
	AttributesService_GetAttributeValue_FullMethodName                  = "/policy.attributes.AttributesService/GetAttributeValue"
	AttributesService_CreateAttributeValue_FullMethodName               = "/policy.attributes.AttributesService/CreateAttributeValue"
	AttributesService_UpdateAttributeValue_FullMethodName               = "/policy.attributes.AttributesService/UpdateAttributeValue"
	AttributesService_DeactivateAttributeValue_FullMethodName           = "/policy.attributes.AttributesService/DeactivateAttributeValue"
	AttributesService_AssignKeyAccessServerToAttribute_FullMethodName   = "/policy.attributes.AttributesService/AssignKeyAccessServerToAttribute"
	AttributesService_RemoveKeyAccessServerFromAttribute_FullMethodName = "/policy.attributes.AttributesService/RemoveKeyAccessServerFromAttribute"
	AttributesService_AssignKeyAccessServerToValue_FullMethodName       = "/policy.attributes.AttributesService/AssignKeyAccessServerToValue"
	AttributesService_RemoveKeyAccessServerFromValue_FullMethodName     = "/policy.attributes.AttributesService/RemoveKeyAccessServerFromValue"
	AttributesService_AssignKeyToAttribute_FullMethodName               = "/policy.attributes.AttributesService/AssignKeyToAttribute"
	AttributesService_RemoveKeyFromAttribute_FullMethodName             = "/policy.attributes.AttributesService/RemoveKeyFromAttribute"
	AttributesService_AssignKeyToValue_FullMethodName                   = "/policy.attributes.AttributesService/AssignKeyToValue"
	AttributesService_RemoveKeyFromValue_FullMethodName                 = "/policy.attributes.AttributesService/RemoveKeyFromValue"
)

// AttributesServiceClient is the client API for AttributesService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AttributesServiceClient interface {
	// --------------------------------------*
	// Attribute RPCs
	// ---------------------------------------
	ListAttributes(ctx context.Context, in *ListAttributesRequest, opts ...grpc.CallOption) (*ListAttributesResponse, error)
	ListAttributeValues(ctx context.Context, in *ListAttributeValuesRequest, opts ...grpc.CallOption) (*ListAttributeValuesResponse, error)
	GetAttribute(ctx context.Context, in *GetAttributeRequest, opts ...grpc.CallOption) (*GetAttributeResponse, error)
	GetAttributeValuesByFqns(ctx context.Context, in *GetAttributeValuesByFqnsRequest, opts ...grpc.CallOption) (*GetAttributeValuesByFqnsResponse, error)
	CreateAttribute(ctx context.Context, in *CreateAttributeRequest, opts ...grpc.CallOption) (*CreateAttributeResponse, error)
	UpdateAttribute(ctx context.Context, in *UpdateAttributeRequest, opts ...grpc.CallOption) (*UpdateAttributeResponse, error)
	DeactivateAttribute(ctx context.Context, in *DeactivateAttributeRequest, opts ...grpc.CallOption) (*DeactivateAttributeResponse, error)
	// --------------------------------------*
	// Value RPCs
	// ---------------------------------------
	GetAttributeValue(ctx context.Context, in *GetAttributeValueRequest, opts ...grpc.CallOption) (*GetAttributeValueResponse, error)
	CreateAttributeValue(ctx context.Context, in *CreateAttributeValueRequest, opts ...grpc.CallOption) (*CreateAttributeValueResponse, error)
	UpdateAttributeValue(ctx context.Context, in *UpdateAttributeValueRequest, opts ...grpc.CallOption) (*UpdateAttributeValueResponse, error)
	DeactivateAttributeValue(ctx context.Context, in *DeactivateAttributeValueRequest, opts ...grpc.CallOption) (*DeactivateAttributeValueResponse, error)
	// --------------------------------------*
	// Attribute <> Key Access Server RPCs
	// ---------------------------------------
	AssignKeyAccessServerToAttribute(ctx context.Context, in *AssignKeyAccessServerToAttributeRequest, opts ...grpc.CallOption) (*AssignKeyAccessServerToAttributeResponse, error)
	RemoveKeyAccessServerFromAttribute(ctx context.Context, in *RemoveKeyAccessServerFromAttributeRequest, opts ...grpc.CallOption) (*RemoveKeyAccessServerFromAttributeResponse, error)
	AssignKeyAccessServerToValue(ctx context.Context, in *AssignKeyAccessServerToValueRequest, opts ...grpc.CallOption) (*AssignKeyAccessServerToValueResponse, error)
	RemoveKeyAccessServerFromValue(ctx context.Context, in *RemoveKeyAccessServerFromValueRequest, opts ...grpc.CallOption) (*RemoveKeyAccessServerFromValueResponse, error)
	AssignKeyToAttribute(ctx context.Context, in *AssignKeyToAttributeRequest, opts ...grpc.CallOption) (*AssignKeyToAttributeResponse, error)
	RemoveKeyFromAttribute(ctx context.Context, in *RemoveKeyFromAttributeRequest, opts ...grpc.CallOption) (*RemoveKeyFromAttributeResponse, error)
	AssignKeyToValue(ctx context.Context, in *AssignKeyToValueRequest, opts ...grpc.CallOption) (*AssignKeyToValueResponse, error)
	RemoveKeyFromValue(ctx context.Context, in *RemoveKeyFromValueRequest, opts ...grpc.CallOption) (*RemoveKeyFromValueResponse, error)
}

type attributesServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAttributesServiceClient(cc grpc.ClientConnInterface) AttributesServiceClient {
	return &attributesServiceClient{cc}
}

func (c *attributesServiceClient) ListAttributes(ctx context.Context, in *ListAttributesRequest, opts ...grpc.CallOption) (*ListAttributesResponse, error) {
	out := new(ListAttributesResponse)
	err := c.cc.Invoke(ctx, AttributesService_ListAttributes_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) ListAttributeValues(ctx context.Context, in *ListAttributeValuesRequest, opts ...grpc.CallOption) (*ListAttributeValuesResponse, error) {
	out := new(ListAttributeValuesResponse)
	err := c.cc.Invoke(ctx, AttributesService_ListAttributeValues_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) GetAttribute(ctx context.Context, in *GetAttributeRequest, opts ...grpc.CallOption) (*GetAttributeResponse, error) {
	out := new(GetAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_GetAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) GetAttributeValuesByFqns(ctx context.Context, in *GetAttributeValuesByFqnsRequest, opts ...grpc.CallOption) (*GetAttributeValuesByFqnsResponse, error) {
	out := new(GetAttributeValuesByFqnsResponse)
	err := c.cc.Invoke(ctx, AttributesService_GetAttributeValuesByFqns_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) CreateAttribute(ctx context.Context, in *CreateAttributeRequest, opts ...grpc.CallOption) (*CreateAttributeResponse, error) {
	out := new(CreateAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_CreateAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) UpdateAttribute(ctx context.Context, in *UpdateAttributeRequest, opts ...grpc.CallOption) (*UpdateAttributeResponse, error) {
	out := new(UpdateAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_UpdateAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) DeactivateAttribute(ctx context.Context, in *DeactivateAttributeRequest, opts ...grpc.CallOption) (*DeactivateAttributeResponse, error) {
	out := new(DeactivateAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_DeactivateAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) GetAttributeValue(ctx context.Context, in *GetAttributeValueRequest, opts ...grpc.CallOption) (*GetAttributeValueResponse, error) {
	out := new(GetAttributeValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_GetAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) CreateAttributeValue(ctx context.Context, in *CreateAttributeValueRequest, opts ...grpc.CallOption) (*CreateAttributeValueResponse, error) {
	out := new(CreateAttributeValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_CreateAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) UpdateAttributeValue(ctx context.Context, in *UpdateAttributeValueRequest, opts ...grpc.CallOption) (*UpdateAttributeValueResponse, error) {
	out := new(UpdateAttributeValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_UpdateAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) DeactivateAttributeValue(ctx context.Context, in *DeactivateAttributeValueRequest, opts ...grpc.CallOption) (*DeactivateAttributeValueResponse, error) {
	out := new(DeactivateAttributeValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_DeactivateAttributeValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) AssignKeyAccessServerToAttribute(ctx context.Context, in *AssignKeyAccessServerToAttributeRequest, opts ...grpc.CallOption) (*AssignKeyAccessServerToAttributeResponse, error) {
	out := new(AssignKeyAccessServerToAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_AssignKeyAccessServerToAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, in *RemoveKeyAccessServerFromAttributeRequest, opts ...grpc.CallOption) (*RemoveKeyAccessServerFromAttributeResponse, error) {
	out := new(RemoveKeyAccessServerFromAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_RemoveKeyAccessServerFromAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) AssignKeyAccessServerToValue(ctx context.Context, in *AssignKeyAccessServerToValueRequest, opts ...grpc.CallOption) (*AssignKeyAccessServerToValueResponse, error) {
	out := new(AssignKeyAccessServerToValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_AssignKeyAccessServerToValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) RemoveKeyAccessServerFromValue(ctx context.Context, in *RemoveKeyAccessServerFromValueRequest, opts ...grpc.CallOption) (*RemoveKeyAccessServerFromValueResponse, error) {
	out := new(RemoveKeyAccessServerFromValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_RemoveKeyAccessServerFromValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) AssignKeyToAttribute(ctx context.Context, in *AssignKeyToAttributeRequest, opts ...grpc.CallOption) (*AssignKeyToAttributeResponse, error) {
	out := new(AssignKeyToAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_AssignKeyToAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) RemoveKeyFromAttribute(ctx context.Context, in *RemoveKeyFromAttributeRequest, opts ...grpc.CallOption) (*RemoveKeyFromAttributeResponse, error) {
	out := new(RemoveKeyFromAttributeResponse)
	err := c.cc.Invoke(ctx, AttributesService_RemoveKeyFromAttribute_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) AssignKeyToValue(ctx context.Context, in *AssignKeyToValueRequest, opts ...grpc.CallOption) (*AssignKeyToValueResponse, error) {
	out := new(AssignKeyToValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_AssignKeyToValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) RemoveKeyFromValue(ctx context.Context, in *RemoveKeyFromValueRequest, opts ...grpc.CallOption) (*RemoveKeyFromValueResponse, error) {
	out := new(RemoveKeyFromValueResponse)
	err := c.cc.Invoke(ctx, AttributesService_RemoveKeyFromValue_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AttributesServiceServer is the server API for AttributesService service.
// All implementations must embed UnimplementedAttributesServiceServer
// for forward compatibility
type AttributesServiceServer interface {
	// --------------------------------------*
	// Attribute RPCs
	// ---------------------------------------
	ListAttributes(context.Context, *ListAttributesRequest) (*ListAttributesResponse, error)
	ListAttributeValues(context.Context, *ListAttributeValuesRequest) (*ListAttributeValuesResponse, error)
	GetAttribute(context.Context, *GetAttributeRequest) (*GetAttributeResponse, error)
	GetAttributeValuesByFqns(context.Context, *GetAttributeValuesByFqnsRequest) (*GetAttributeValuesByFqnsResponse, error)
	CreateAttribute(context.Context, *CreateAttributeRequest) (*CreateAttributeResponse, error)
	UpdateAttribute(context.Context, *UpdateAttributeRequest) (*UpdateAttributeResponse, error)
	DeactivateAttribute(context.Context, *DeactivateAttributeRequest) (*DeactivateAttributeResponse, error)
	// --------------------------------------*
	// Value RPCs
	// ---------------------------------------
	GetAttributeValue(context.Context, *GetAttributeValueRequest) (*GetAttributeValueResponse, error)
	CreateAttributeValue(context.Context, *CreateAttributeValueRequest) (*CreateAttributeValueResponse, error)
	UpdateAttributeValue(context.Context, *UpdateAttributeValueRequest) (*UpdateAttributeValueResponse, error)
	DeactivateAttributeValue(context.Context, *DeactivateAttributeValueRequest) (*DeactivateAttributeValueResponse, error)
	// --------------------------------------*
	// Attribute <> Key Access Server RPCs
	// ---------------------------------------
	AssignKeyAccessServerToAttribute(context.Context, *AssignKeyAccessServerToAttributeRequest) (*AssignKeyAccessServerToAttributeResponse, error)
	RemoveKeyAccessServerFromAttribute(context.Context, *RemoveKeyAccessServerFromAttributeRequest) (*RemoveKeyAccessServerFromAttributeResponse, error)
	AssignKeyAccessServerToValue(context.Context, *AssignKeyAccessServerToValueRequest) (*AssignKeyAccessServerToValueResponse, error)
	RemoveKeyAccessServerFromValue(context.Context, *RemoveKeyAccessServerFromValueRequest) (*RemoveKeyAccessServerFromValueResponse, error)
	AssignKeyToAttribute(context.Context, *AssignKeyToAttributeRequest) (*AssignKeyToAttributeResponse, error)
	RemoveKeyFromAttribute(context.Context, *RemoveKeyFromAttributeRequest) (*RemoveKeyFromAttributeResponse, error)
	AssignKeyToValue(context.Context, *AssignKeyToValueRequest) (*AssignKeyToValueResponse, error)
	RemoveKeyFromValue(context.Context, *RemoveKeyFromValueRequest) (*RemoveKeyFromValueResponse, error)
	mustEmbedUnimplementedAttributesServiceServer()
}

// UnimplementedAttributesServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAttributesServiceServer struct {
}

func (UnimplementedAttributesServiceServer) ListAttributes(context.Context, *ListAttributesRequest) (*ListAttributesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAttributes not implemented")
}
func (UnimplementedAttributesServiceServer) ListAttributeValues(context.Context, *ListAttributeValuesRequest) (*ListAttributeValuesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAttributeValues not implemented")
}
func (UnimplementedAttributesServiceServer) GetAttribute(context.Context, *GetAttributeRequest) (*GetAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) GetAttributeValuesByFqns(context.Context, *GetAttributeValuesByFqnsRequest) (*GetAttributeValuesByFqnsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttributeValuesByFqns not implemented")
}
func (UnimplementedAttributesServiceServer) CreateAttribute(context.Context, *CreateAttributeRequest) (*CreateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) UpdateAttribute(context.Context, *UpdateAttributeRequest) (*UpdateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) DeactivateAttribute(context.Context, *DeactivateAttributeRequest) (*DeactivateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeactivateAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) GetAttributeValue(context.Context, *GetAttributeValueRequest) (*GetAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttributeValue not implemented")
}
func (UnimplementedAttributesServiceServer) CreateAttributeValue(context.Context, *CreateAttributeValueRequest) (*CreateAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAttributeValue not implemented")
}
func (UnimplementedAttributesServiceServer) UpdateAttributeValue(context.Context, *UpdateAttributeValueRequest) (*UpdateAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAttributeValue not implemented")
}
func (UnimplementedAttributesServiceServer) DeactivateAttributeValue(context.Context, *DeactivateAttributeValueRequest) (*DeactivateAttributeValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeactivateAttributeValue not implemented")
}
func (UnimplementedAttributesServiceServer) AssignKeyAccessServerToAttribute(context.Context, *AssignKeyAccessServerToAttributeRequest) (*AssignKeyAccessServerToAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignKeyAccessServerToAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) RemoveKeyAccessServerFromAttribute(context.Context, *RemoveKeyAccessServerFromAttributeRequest) (*RemoveKeyAccessServerFromAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveKeyAccessServerFromAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) AssignKeyAccessServerToValue(context.Context, *AssignKeyAccessServerToValueRequest) (*AssignKeyAccessServerToValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignKeyAccessServerToValue not implemented")
}
func (UnimplementedAttributesServiceServer) RemoveKeyAccessServerFromValue(context.Context, *RemoveKeyAccessServerFromValueRequest) (*RemoveKeyAccessServerFromValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveKeyAccessServerFromValue not implemented")
}
func (UnimplementedAttributesServiceServer) AssignKeyToAttribute(context.Context, *AssignKeyToAttributeRequest) (*AssignKeyToAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignKeyToAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) RemoveKeyFromAttribute(context.Context, *RemoveKeyFromAttributeRequest) (*RemoveKeyFromAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveKeyFromAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) AssignKeyToValue(context.Context, *AssignKeyToValueRequest) (*AssignKeyToValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignKeyToValue not implemented")
}
func (UnimplementedAttributesServiceServer) RemoveKeyFromValue(context.Context, *RemoveKeyFromValueRequest) (*RemoveKeyFromValueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveKeyFromValue not implemented")
}
func (UnimplementedAttributesServiceServer) mustEmbedUnimplementedAttributesServiceServer() {}

// UnsafeAttributesServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AttributesServiceServer will
// result in compilation errors.
type UnsafeAttributesServiceServer interface {
	mustEmbedUnimplementedAttributesServiceServer()
}

func RegisterAttributesServiceServer(s grpc.ServiceRegistrar, srv AttributesServiceServer) {
	s.RegisterService(&AttributesService_ServiceDesc, srv)
}

func _AttributesService_ListAttributes_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAttributesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).ListAttributes(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_ListAttributes_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).ListAttributes(ctx, req.(*ListAttributesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_ListAttributeValues_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAttributeValuesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).ListAttributeValues(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_ListAttributeValues_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).ListAttributeValues(ctx, req.(*ListAttributeValuesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_GetAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).GetAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_GetAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).GetAttribute(ctx, req.(*GetAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_GetAttributeValuesByFqns_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttributeValuesByFqnsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).GetAttributeValuesByFqns(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_GetAttributeValuesByFqns_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).GetAttributeValuesByFqns(ctx, req.(*GetAttributeValuesByFqnsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_CreateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).CreateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_CreateAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).CreateAttribute(ctx, req.(*CreateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_UpdateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).UpdateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_UpdateAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).UpdateAttribute(ctx, req.(*UpdateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_DeactivateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeactivateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).DeactivateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_DeactivateAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).DeactivateAttribute(ctx, req.(*DeactivateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_GetAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).GetAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_GetAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).GetAttributeValue(ctx, req.(*GetAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_CreateAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).CreateAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_CreateAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).CreateAttributeValue(ctx, req.(*CreateAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_UpdateAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).UpdateAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_UpdateAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).UpdateAttributeValue(ctx, req.(*UpdateAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_DeactivateAttributeValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeactivateAttributeValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).DeactivateAttributeValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_DeactivateAttributeValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).DeactivateAttributeValue(ctx, req.(*DeactivateAttributeValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_AssignKeyAccessServerToAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssignKeyAccessServerToAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).AssignKeyAccessServerToAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_AssignKeyAccessServerToAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).AssignKeyAccessServerToAttribute(ctx, req.(*AssignKeyAccessServerToAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_RemoveKeyAccessServerFromAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveKeyAccessServerFromAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).RemoveKeyAccessServerFromAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_RemoveKeyAccessServerFromAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).RemoveKeyAccessServerFromAttribute(ctx, req.(*RemoveKeyAccessServerFromAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_AssignKeyAccessServerToValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssignKeyAccessServerToValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).AssignKeyAccessServerToValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_AssignKeyAccessServerToValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).AssignKeyAccessServerToValue(ctx, req.(*AssignKeyAccessServerToValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_RemoveKeyAccessServerFromValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveKeyAccessServerFromValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).RemoveKeyAccessServerFromValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_RemoveKeyAccessServerFromValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).RemoveKeyAccessServerFromValue(ctx, req.(*RemoveKeyAccessServerFromValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_AssignKeyToAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssignKeyToAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).AssignKeyToAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_AssignKeyToAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).AssignKeyToAttribute(ctx, req.(*AssignKeyToAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_RemoveKeyFromAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveKeyFromAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).RemoveKeyFromAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_RemoveKeyFromAttribute_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).RemoveKeyFromAttribute(ctx, req.(*RemoveKeyFromAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_AssignKeyToValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssignKeyToValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).AssignKeyToValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_AssignKeyToValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).AssignKeyToValue(ctx, req.(*AssignKeyToValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_RemoveKeyFromValue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveKeyFromValueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).RemoveKeyFromValue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttributesService_RemoveKeyFromValue_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).RemoveKeyFromValue(ctx, req.(*RemoveKeyFromValueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AttributesService_ServiceDesc is the grpc.ServiceDesc for AttributesService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AttributesService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "policy.attributes.AttributesService",
	HandlerType: (*AttributesServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListAttributes",
			Handler:    _AttributesService_ListAttributes_Handler,
		},
		{
			MethodName: "ListAttributeValues",
			Handler:    _AttributesService_ListAttributeValues_Handler,
		},
		{
			MethodName: "GetAttribute",
			Handler:    _AttributesService_GetAttribute_Handler,
		},
		{
			MethodName: "GetAttributeValuesByFqns",
			Handler:    _AttributesService_GetAttributeValuesByFqns_Handler,
		},
		{
			MethodName: "CreateAttribute",
			Handler:    _AttributesService_CreateAttribute_Handler,
		},
		{
			MethodName: "UpdateAttribute",
			Handler:    _AttributesService_UpdateAttribute_Handler,
		},
		{
			MethodName: "DeactivateAttribute",
			Handler:    _AttributesService_DeactivateAttribute_Handler,
		},
		{
			MethodName: "GetAttributeValue",
			Handler:    _AttributesService_GetAttributeValue_Handler,
		},
		{
			MethodName: "CreateAttributeValue",
			Handler:    _AttributesService_CreateAttributeValue_Handler,
		},
		{
			MethodName: "UpdateAttributeValue",
			Handler:    _AttributesService_UpdateAttributeValue_Handler,
		},
		{
			MethodName: "DeactivateAttributeValue",
			Handler:    _AttributesService_DeactivateAttributeValue_Handler,
		},
		{
			MethodName: "AssignKeyAccessServerToAttribute",
			Handler:    _AttributesService_AssignKeyAccessServerToAttribute_Handler,
		},
		{
			MethodName: "RemoveKeyAccessServerFromAttribute",
			Handler:    _AttributesService_RemoveKeyAccessServerFromAttribute_Handler,
		},
		{
			MethodName: "AssignKeyAccessServerToValue",
			Handler:    _AttributesService_AssignKeyAccessServerToValue_Handler,
		},
		{
			MethodName: "RemoveKeyAccessServerFromValue",
			Handler:    _AttributesService_RemoveKeyAccessServerFromValue_Handler,
		},
		{
			MethodName: "AssignKeyToAttribute",
			Handler:    _AttributesService_AssignKeyToAttribute_Handler,
		},
		{
			MethodName: "RemoveKeyFromAttribute",
			Handler:    _AttributesService_RemoveKeyFromAttribute_Handler,
		},
		{
			MethodName: "AssignKeyToValue",
			Handler:    _AttributesService_AssignKeyToValue_Handler,
		},
		{
			MethodName: "RemoveKeyFromValue",
			Handler:    _AttributesService_RemoveKeyFromValue_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "policy/attributes/attributes.proto",
}
