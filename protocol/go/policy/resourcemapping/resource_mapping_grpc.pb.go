// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: policy/resourcemapping/resource_mapping.proto

package resourcemapping

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
	ResourceMappingService_ListResourceMappingGroups_FullMethodName       = "/policy.resourcemapping.ResourceMappingService/ListResourceMappingGroups"
	ResourceMappingService_ListResourceMappingGroupsByFqns_FullMethodName = "/policy.resourcemapping.ResourceMappingService/ListResourceMappingGroupsByFqns"
	ResourceMappingService_GetResourceMappingGroup_FullMethodName         = "/policy.resourcemapping.ResourceMappingService/GetResourceMappingGroup"
	ResourceMappingService_CreateResourceMappingGroup_FullMethodName      = "/policy.resourcemapping.ResourceMappingService/CreateResourceMappingGroup"
	ResourceMappingService_UpdateResourceMappingGroup_FullMethodName      = "/policy.resourcemapping.ResourceMappingService/UpdateResourceMappingGroup"
	ResourceMappingService_DeleteResourceMappingGroup_FullMethodName      = "/policy.resourcemapping.ResourceMappingService/DeleteResourceMappingGroup"
	ResourceMappingService_ListResourceMappings_FullMethodName            = "/policy.resourcemapping.ResourceMappingService/ListResourceMappings"
	ResourceMappingService_GetResourceMapping_FullMethodName              = "/policy.resourcemapping.ResourceMappingService/GetResourceMapping"
	ResourceMappingService_CreateResourceMapping_FullMethodName           = "/policy.resourcemapping.ResourceMappingService/CreateResourceMapping"
	ResourceMappingService_UpdateResourceMapping_FullMethodName           = "/policy.resourcemapping.ResourceMappingService/UpdateResourceMapping"
	ResourceMappingService_DeleteResourceMapping_FullMethodName           = "/policy.resourcemapping.ResourceMappingService/DeleteResourceMapping"
)

// ResourceMappingServiceClient is the client API for ResourceMappingService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ResourceMappingServiceClient interface {
	ListResourceMappingGroups(ctx context.Context, in *ListResourceMappingGroupsRequest, opts ...grpc.CallOption) (*ListResourceMappingGroupsResponse, error)
	ListResourceMappingGroupsByFqns(ctx context.Context, in *ListResourceMappingGroupsByFqnsRequest, opts ...grpc.CallOption) (*ListResourceMappingGroupsByFqnsResponse, error)
	GetResourceMappingGroup(ctx context.Context, in *GetResourceMappingGroupRequest, opts ...grpc.CallOption) (*GetResourceMappingGroupResponse, error)
	CreateResourceMappingGroup(ctx context.Context, in *CreateResourceMappingGroupRequest, opts ...grpc.CallOption) (*CreateResourceMappingGroupResponse, error)
	UpdateResourceMappingGroup(ctx context.Context, in *UpdateResourceMappingGroupRequest, opts ...grpc.CallOption) (*UpdateResourceMappingGroupResponse, error)
	DeleteResourceMappingGroup(ctx context.Context, in *DeleteResourceMappingGroupRequest, opts ...grpc.CallOption) (*DeleteResourceMappingGroupResponse, error)
	ListResourceMappings(ctx context.Context, in *ListResourceMappingsRequest, opts ...grpc.CallOption) (*ListResourceMappingsResponse, error)
	GetResourceMapping(ctx context.Context, in *GetResourceMappingRequest, opts ...grpc.CallOption) (*GetResourceMappingResponse, error)
	CreateResourceMapping(ctx context.Context, in *CreateResourceMappingRequest, opts ...grpc.CallOption) (*CreateResourceMappingResponse, error)
	UpdateResourceMapping(ctx context.Context, in *UpdateResourceMappingRequest, opts ...grpc.CallOption) (*UpdateResourceMappingResponse, error)
	DeleteResourceMapping(ctx context.Context, in *DeleteResourceMappingRequest, opts ...grpc.CallOption) (*DeleteResourceMappingResponse, error)
}

type resourceMappingServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewResourceMappingServiceClient(cc grpc.ClientConnInterface) ResourceMappingServiceClient {
	return &resourceMappingServiceClient{cc}
}

func (c *resourceMappingServiceClient) ListResourceMappingGroups(ctx context.Context, in *ListResourceMappingGroupsRequest, opts ...grpc.CallOption) (*ListResourceMappingGroupsResponse, error) {
	out := new(ListResourceMappingGroupsResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_ListResourceMappingGroups_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) ListResourceMappingGroupsByFqns(ctx context.Context, in *ListResourceMappingGroupsByFqnsRequest, opts ...grpc.CallOption) (*ListResourceMappingGroupsByFqnsResponse, error) {
	out := new(ListResourceMappingGroupsByFqnsResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_ListResourceMappingGroupsByFqns_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) GetResourceMappingGroup(ctx context.Context, in *GetResourceMappingGroupRequest, opts ...grpc.CallOption) (*GetResourceMappingGroupResponse, error) {
	out := new(GetResourceMappingGroupResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_GetResourceMappingGroup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) CreateResourceMappingGroup(ctx context.Context, in *CreateResourceMappingGroupRequest, opts ...grpc.CallOption) (*CreateResourceMappingGroupResponse, error) {
	out := new(CreateResourceMappingGroupResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_CreateResourceMappingGroup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) UpdateResourceMappingGroup(ctx context.Context, in *UpdateResourceMappingGroupRequest, opts ...grpc.CallOption) (*UpdateResourceMappingGroupResponse, error) {
	out := new(UpdateResourceMappingGroupResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_UpdateResourceMappingGroup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) DeleteResourceMappingGroup(ctx context.Context, in *DeleteResourceMappingGroupRequest, opts ...grpc.CallOption) (*DeleteResourceMappingGroupResponse, error) {
	out := new(DeleteResourceMappingGroupResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_DeleteResourceMappingGroup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) ListResourceMappings(ctx context.Context, in *ListResourceMappingsRequest, opts ...grpc.CallOption) (*ListResourceMappingsResponse, error) {
	out := new(ListResourceMappingsResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_ListResourceMappings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) GetResourceMapping(ctx context.Context, in *GetResourceMappingRequest, opts ...grpc.CallOption) (*GetResourceMappingResponse, error) {
	out := new(GetResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_GetResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) CreateResourceMapping(ctx context.Context, in *CreateResourceMappingRequest, opts ...grpc.CallOption) (*CreateResourceMappingResponse, error) {
	out := new(CreateResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_CreateResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) UpdateResourceMapping(ctx context.Context, in *UpdateResourceMappingRequest, opts ...grpc.CallOption) (*UpdateResourceMappingResponse, error) {
	out := new(UpdateResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_UpdateResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) DeleteResourceMapping(ctx context.Context, in *DeleteResourceMappingRequest, opts ...grpc.CallOption) (*DeleteResourceMappingResponse, error) {
	out := new(DeleteResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_DeleteResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceMappingServiceServer is the server API for ResourceMappingService service.
// All implementations must embed UnimplementedResourceMappingServiceServer
// for forward compatibility
type ResourceMappingServiceServer interface {
	ListResourceMappingGroups(context.Context, *ListResourceMappingGroupsRequest) (*ListResourceMappingGroupsResponse, error)
	ListResourceMappingGroupsByFqns(context.Context, *ListResourceMappingGroupsByFqnsRequest) (*ListResourceMappingGroupsByFqnsResponse, error)
	GetResourceMappingGroup(context.Context, *GetResourceMappingGroupRequest) (*GetResourceMappingGroupResponse, error)
	CreateResourceMappingGroup(context.Context, *CreateResourceMappingGroupRequest) (*CreateResourceMappingGroupResponse, error)
	UpdateResourceMappingGroup(context.Context, *UpdateResourceMappingGroupRequest) (*UpdateResourceMappingGroupResponse, error)
	DeleteResourceMappingGroup(context.Context, *DeleteResourceMappingGroupRequest) (*DeleteResourceMappingGroupResponse, error)
	ListResourceMappings(context.Context, *ListResourceMappingsRequest) (*ListResourceMappingsResponse, error)
	GetResourceMapping(context.Context, *GetResourceMappingRequest) (*GetResourceMappingResponse, error)
	CreateResourceMapping(context.Context, *CreateResourceMappingRequest) (*CreateResourceMappingResponse, error)
	UpdateResourceMapping(context.Context, *UpdateResourceMappingRequest) (*UpdateResourceMappingResponse, error)
	DeleteResourceMapping(context.Context, *DeleteResourceMappingRequest) (*DeleteResourceMappingResponse, error)
	mustEmbedUnimplementedResourceMappingServiceServer()
}

// UnimplementedResourceMappingServiceServer must be embedded to have forward compatible implementations.
type UnimplementedResourceMappingServiceServer struct {
}

func (UnimplementedResourceMappingServiceServer) ListResourceMappingGroups(context.Context, *ListResourceMappingGroupsRequest) (*ListResourceMappingGroupsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListResourceMappingGroups not implemented")
}
func (UnimplementedResourceMappingServiceServer) ListResourceMappingGroupsByFqns(context.Context, *ListResourceMappingGroupsByFqnsRequest) (*ListResourceMappingGroupsByFqnsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListResourceMappingGroupsByFqns not implemented")
}
func (UnimplementedResourceMappingServiceServer) GetResourceMappingGroup(context.Context, *GetResourceMappingGroupRequest) (*GetResourceMappingGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetResourceMappingGroup not implemented")
}
func (UnimplementedResourceMappingServiceServer) CreateResourceMappingGroup(context.Context, *CreateResourceMappingGroupRequest) (*CreateResourceMappingGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateResourceMappingGroup not implemented")
}
func (UnimplementedResourceMappingServiceServer) UpdateResourceMappingGroup(context.Context, *UpdateResourceMappingGroupRequest) (*UpdateResourceMappingGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateResourceMappingGroup not implemented")
}
func (UnimplementedResourceMappingServiceServer) DeleteResourceMappingGroup(context.Context, *DeleteResourceMappingGroupRequest) (*DeleteResourceMappingGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteResourceMappingGroup not implemented")
}
func (UnimplementedResourceMappingServiceServer) ListResourceMappings(context.Context, *ListResourceMappingsRequest) (*ListResourceMappingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListResourceMappings not implemented")
}
func (UnimplementedResourceMappingServiceServer) GetResourceMapping(context.Context, *GetResourceMappingRequest) (*GetResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) CreateResourceMapping(context.Context, *CreateResourceMappingRequest) (*CreateResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) UpdateResourceMapping(context.Context, *UpdateResourceMappingRequest) (*UpdateResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) DeleteResourceMapping(context.Context, *DeleteResourceMappingRequest) (*DeleteResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) mustEmbedUnimplementedResourceMappingServiceServer() {
}

// UnsafeResourceMappingServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ResourceMappingServiceServer will
// result in compilation errors.
type UnsafeResourceMappingServiceServer interface {
	mustEmbedUnimplementedResourceMappingServiceServer()
}

func RegisterResourceMappingServiceServer(s grpc.ServiceRegistrar, srv ResourceMappingServiceServer) {
	s.RegisterService(&ResourceMappingService_ServiceDesc, srv)
}

func _ResourceMappingService_ListResourceMappingGroups_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListResourceMappingGroupsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).ListResourceMappingGroups(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_ListResourceMappingGroups_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).ListResourceMappingGroups(ctx, req.(*ListResourceMappingGroupsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_ListResourceMappingGroupsByFqns_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListResourceMappingGroupsByFqnsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).ListResourceMappingGroupsByFqns(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_ListResourceMappingGroupsByFqns_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).ListResourceMappingGroupsByFqns(ctx, req.(*ListResourceMappingGroupsByFqnsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_GetResourceMappingGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetResourceMappingGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).GetResourceMappingGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_GetResourceMappingGroup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).GetResourceMappingGroup(ctx, req.(*GetResourceMappingGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_CreateResourceMappingGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateResourceMappingGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).CreateResourceMappingGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_CreateResourceMappingGroup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).CreateResourceMappingGroup(ctx, req.(*CreateResourceMappingGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_UpdateResourceMappingGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateResourceMappingGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).UpdateResourceMappingGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_UpdateResourceMappingGroup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).UpdateResourceMappingGroup(ctx, req.(*UpdateResourceMappingGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_DeleteResourceMappingGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteResourceMappingGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).DeleteResourceMappingGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_DeleteResourceMappingGroup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).DeleteResourceMappingGroup(ctx, req.(*DeleteResourceMappingGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_ListResourceMappings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListResourceMappingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).ListResourceMappings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_ListResourceMappings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).ListResourceMappings(ctx, req.(*ListResourceMappingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_GetResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).GetResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_GetResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).GetResourceMapping(ctx, req.(*GetResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_CreateResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).CreateResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_CreateResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).CreateResourceMapping(ctx, req.(*CreateResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_UpdateResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).UpdateResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_UpdateResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).UpdateResourceMapping(ctx, req.(*UpdateResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_DeleteResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).DeleteResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_DeleteResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).DeleteResourceMapping(ctx, req.(*DeleteResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ResourceMappingService_ServiceDesc is the grpc.ServiceDesc for ResourceMappingService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ResourceMappingService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "policy.resourcemapping.ResourceMappingService",
	HandlerType: (*ResourceMappingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListResourceMappingGroups",
			Handler:    _ResourceMappingService_ListResourceMappingGroups_Handler,
		},
		{
			MethodName: "ListResourceMappingGroupsByFqns",
			Handler:    _ResourceMappingService_ListResourceMappingGroupsByFqns_Handler,
		},
		{
			MethodName: "GetResourceMappingGroup",
			Handler:    _ResourceMappingService_GetResourceMappingGroup_Handler,
		},
		{
			MethodName: "CreateResourceMappingGroup",
			Handler:    _ResourceMappingService_CreateResourceMappingGroup_Handler,
		},
		{
			MethodName: "UpdateResourceMappingGroup",
			Handler:    _ResourceMappingService_UpdateResourceMappingGroup_Handler,
		},
		{
			MethodName: "DeleteResourceMappingGroup",
			Handler:    _ResourceMappingService_DeleteResourceMappingGroup_Handler,
		},
		{
			MethodName: "ListResourceMappings",
			Handler:    _ResourceMappingService_ListResourceMappings_Handler,
		},
		{
			MethodName: "GetResourceMapping",
			Handler:    _ResourceMappingService_GetResourceMapping_Handler,
		},
		{
			MethodName: "CreateResourceMapping",
			Handler:    _ResourceMappingService_CreateResourceMapping_Handler,
		},
		{
			MethodName: "UpdateResourceMapping",
			Handler:    _ResourceMappingService_UpdateResourceMapping_Handler,
		},
		{
			MethodName: "DeleteResourceMapping",
			Handler:    _ResourceMappingService_DeleteResourceMapping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "policy/resourcemapping/resource_mapping.proto",
}
