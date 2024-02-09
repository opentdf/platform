// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: subjectmapping/subject_mapping.proto

package subjectmapping

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
	SubjectMappingService_GetSubjectSet_FullMethodName        = "/subjectmapping.SubjectMappingService/GetSubjectSet"
	SubjectMappingService_CreateSubjectSet_FullMethodName     = "/subjectmapping.SubjectMappingService/CreateSubjectSet"
	SubjectMappingService_UpdateSubjectSet_FullMethodName     = "/subjectmapping.SubjectMappingService/UpdateSubjectSet"
	SubjectMappingService_DeleteSubjectSet_FullMethodName     = "/subjectmapping.SubjectMappingService/DeleteSubjectSet"
	SubjectMappingService_ListSubjectSets_FullMethodName      = "/subjectmapping.SubjectMappingService/ListSubjectSets"
	SubjectMappingService_MatchSubjectMappings_FullMethodName = "/subjectmapping.SubjectMappingService/MatchSubjectMappings"
	SubjectMappingService_ListSubjectMappings_FullMethodName  = "/subjectmapping.SubjectMappingService/ListSubjectMappings"
	SubjectMappingService_GetSubjectMapping_FullMethodName    = "/subjectmapping.SubjectMappingService/GetSubjectMapping"
	SubjectMappingService_CreateSubjectMapping_FullMethodName = "/subjectmapping.SubjectMappingService/CreateSubjectMapping"
	SubjectMappingService_UpdateSubjectMapping_FullMethodName = "/subjectmapping.SubjectMappingService/UpdateSubjectMapping"
	SubjectMappingService_DeleteSubjectMapping_FullMethodName = "/subjectmapping.SubjectMappingService/DeleteSubjectMapping"
)

// SubjectMappingServiceClient is the client API for SubjectMappingService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SubjectMappingServiceClient interface {
	GetSubjectSet(ctx context.Context, in *GetSubjectSetRequest, opts ...grpc.CallOption) (*GetSubjectSetResponse, error)
	CreateSubjectSet(ctx context.Context, in *CreateSubjectSetRequest, opts ...grpc.CallOption) (*CreateSubjectSetResponse, error)
	UpdateSubjectSet(ctx context.Context, in *UpdateSubjectSetRequest, opts ...grpc.CallOption) (*UpdateSubjectSetResponse, error)
	DeleteSubjectSet(ctx context.Context, in *DeleteSubjectSetRequest, opts ...grpc.CallOption) (*DeleteSubjectSetResponse, error)
	ListSubjectSets(ctx context.Context, in *ListSubjectSetsRequest, opts ...grpc.CallOption) (*ListSubjectSetsResponse, error)
	// Find matching Subject Mappings for a given Subject
	MatchSubjectMappings(ctx context.Context, in *MatchSubjectMappingsRequest, opts ...grpc.CallOption) (*MatchSubjectMappingsResponse, error)
	ListSubjectMappings(ctx context.Context, in *ListSubjectMappingsRequest, opts ...grpc.CallOption) (*ListSubjectMappingsResponse, error)
	GetSubjectMapping(ctx context.Context, in *GetSubjectMappingRequest, opts ...grpc.CallOption) (*GetSubjectMappingResponse, error)
	CreateSubjectMapping(ctx context.Context, in *CreateSubjectMappingRequest, opts ...grpc.CallOption) (*CreateSubjectMappingResponse, error)
	UpdateSubjectMapping(ctx context.Context, in *UpdateSubjectMappingRequest, opts ...grpc.CallOption) (*UpdateSubjectMappingResponse, error)
	DeleteSubjectMapping(ctx context.Context, in *DeleteSubjectMappingRequest, opts ...grpc.CallOption) (*DeleteSubjectMappingResponse, error)
}

type subjectMappingServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSubjectMappingServiceClient(cc grpc.ClientConnInterface) SubjectMappingServiceClient {
	return &subjectMappingServiceClient{cc}
}

func (c *subjectMappingServiceClient) GetSubjectSet(ctx context.Context, in *GetSubjectSetRequest, opts ...grpc.CallOption) (*GetSubjectSetResponse, error) {
	out := new(GetSubjectSetResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_GetSubjectSet_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) CreateSubjectSet(ctx context.Context, in *CreateSubjectSetRequest, opts ...grpc.CallOption) (*CreateSubjectSetResponse, error) {
	out := new(CreateSubjectSetResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_CreateSubjectSet_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) UpdateSubjectSet(ctx context.Context, in *UpdateSubjectSetRequest, opts ...grpc.CallOption) (*UpdateSubjectSetResponse, error) {
	out := new(UpdateSubjectSetResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_UpdateSubjectSet_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) DeleteSubjectSet(ctx context.Context, in *DeleteSubjectSetRequest, opts ...grpc.CallOption) (*DeleteSubjectSetResponse, error) {
	out := new(DeleteSubjectSetResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_DeleteSubjectSet_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) ListSubjectSets(ctx context.Context, in *ListSubjectSetsRequest, opts ...grpc.CallOption) (*ListSubjectSetsResponse, error) {
	out := new(ListSubjectSetsResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_ListSubjectSets_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) MatchSubjectMappings(ctx context.Context, in *MatchSubjectMappingsRequest, opts ...grpc.CallOption) (*MatchSubjectMappingsResponse, error) {
	out := new(MatchSubjectMappingsResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_MatchSubjectMappings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) ListSubjectMappings(ctx context.Context, in *ListSubjectMappingsRequest, opts ...grpc.CallOption) (*ListSubjectMappingsResponse, error) {
	out := new(ListSubjectMappingsResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_ListSubjectMappings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) GetSubjectMapping(ctx context.Context, in *GetSubjectMappingRequest, opts ...grpc.CallOption) (*GetSubjectMappingResponse, error) {
	out := new(GetSubjectMappingResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_GetSubjectMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) CreateSubjectMapping(ctx context.Context, in *CreateSubjectMappingRequest, opts ...grpc.CallOption) (*CreateSubjectMappingResponse, error) {
	out := new(CreateSubjectMappingResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_CreateSubjectMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) UpdateSubjectMapping(ctx context.Context, in *UpdateSubjectMappingRequest, opts ...grpc.CallOption) (*UpdateSubjectMappingResponse, error) {
	out := new(UpdateSubjectMappingResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_UpdateSubjectMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *subjectMappingServiceClient) DeleteSubjectMapping(ctx context.Context, in *DeleteSubjectMappingRequest, opts ...grpc.CallOption) (*DeleteSubjectMappingResponse, error) {
	out := new(DeleteSubjectMappingResponse)
	err := c.cc.Invoke(ctx, SubjectMappingService_DeleteSubjectMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SubjectMappingServiceServer is the server API for SubjectMappingService service.
// All implementations must embed UnimplementedSubjectMappingServiceServer
// for forward compatibility
type SubjectMappingServiceServer interface {
	GetSubjectSet(context.Context, *GetSubjectSetRequest) (*GetSubjectSetResponse, error)
	CreateSubjectSet(context.Context, *CreateSubjectSetRequest) (*CreateSubjectSetResponse, error)
	UpdateSubjectSet(context.Context, *UpdateSubjectSetRequest) (*UpdateSubjectSetResponse, error)
	DeleteSubjectSet(context.Context, *DeleteSubjectSetRequest) (*DeleteSubjectSetResponse, error)
	ListSubjectSets(context.Context, *ListSubjectSetsRequest) (*ListSubjectSetsResponse, error)
	// Find matching Subject Mappings for a given Subject
	MatchSubjectMappings(context.Context, *MatchSubjectMappingsRequest) (*MatchSubjectMappingsResponse, error)
	ListSubjectMappings(context.Context, *ListSubjectMappingsRequest) (*ListSubjectMappingsResponse, error)
	GetSubjectMapping(context.Context, *GetSubjectMappingRequest) (*GetSubjectMappingResponse, error)
	CreateSubjectMapping(context.Context, *CreateSubjectMappingRequest) (*CreateSubjectMappingResponse, error)
	UpdateSubjectMapping(context.Context, *UpdateSubjectMappingRequest) (*UpdateSubjectMappingResponse, error)
	DeleteSubjectMapping(context.Context, *DeleteSubjectMappingRequest) (*DeleteSubjectMappingResponse, error)
	mustEmbedUnimplementedSubjectMappingServiceServer()
}

// UnimplementedSubjectMappingServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSubjectMappingServiceServer struct {
}

func (UnimplementedSubjectMappingServiceServer) GetSubjectSet(context.Context, *GetSubjectSetRequest) (*GetSubjectSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSubjectSet not implemented")
}
func (UnimplementedSubjectMappingServiceServer) CreateSubjectSet(context.Context, *CreateSubjectSetRequest) (*CreateSubjectSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSubjectSet not implemented")
}
func (UnimplementedSubjectMappingServiceServer) UpdateSubjectSet(context.Context, *UpdateSubjectSetRequest) (*UpdateSubjectSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateSubjectSet not implemented")
}
func (UnimplementedSubjectMappingServiceServer) DeleteSubjectSet(context.Context, *DeleteSubjectSetRequest) (*DeleteSubjectSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteSubjectSet not implemented")
}
func (UnimplementedSubjectMappingServiceServer) ListSubjectSets(context.Context, *ListSubjectSetsRequest) (*ListSubjectSetsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListSubjectSets not implemented")
}
func (UnimplementedSubjectMappingServiceServer) MatchSubjectMappings(context.Context, *MatchSubjectMappingsRequest) (*MatchSubjectMappingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MatchSubjectMappings not implemented")
}
func (UnimplementedSubjectMappingServiceServer) ListSubjectMappings(context.Context, *ListSubjectMappingsRequest) (*ListSubjectMappingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListSubjectMappings not implemented")
}
func (UnimplementedSubjectMappingServiceServer) GetSubjectMapping(context.Context, *GetSubjectMappingRequest) (*GetSubjectMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSubjectMapping not implemented")
}
func (UnimplementedSubjectMappingServiceServer) CreateSubjectMapping(context.Context, *CreateSubjectMappingRequest) (*CreateSubjectMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSubjectMapping not implemented")
}
func (UnimplementedSubjectMappingServiceServer) UpdateSubjectMapping(context.Context, *UpdateSubjectMappingRequest) (*UpdateSubjectMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateSubjectMapping not implemented")
}
func (UnimplementedSubjectMappingServiceServer) DeleteSubjectMapping(context.Context, *DeleteSubjectMappingRequest) (*DeleteSubjectMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteSubjectMapping not implemented")
}
func (UnimplementedSubjectMappingServiceServer) mustEmbedUnimplementedSubjectMappingServiceServer() {}

// UnsafeSubjectMappingServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SubjectMappingServiceServer will
// result in compilation errors.
type UnsafeSubjectMappingServiceServer interface {
	mustEmbedUnimplementedSubjectMappingServiceServer()
}

func RegisterSubjectMappingServiceServer(s grpc.ServiceRegistrar, srv SubjectMappingServiceServer) {
	s.RegisterService(&SubjectMappingService_ServiceDesc, srv)
}

func _SubjectMappingService_GetSubjectSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSubjectSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).GetSubjectSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_GetSubjectSet_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).GetSubjectSet(ctx, req.(*GetSubjectSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_CreateSubjectSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSubjectSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).CreateSubjectSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_CreateSubjectSet_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).CreateSubjectSet(ctx, req.(*CreateSubjectSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_UpdateSubjectSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateSubjectSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).UpdateSubjectSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_UpdateSubjectSet_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).UpdateSubjectSet(ctx, req.(*UpdateSubjectSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_DeleteSubjectSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSubjectSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).DeleteSubjectSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_DeleteSubjectSet_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).DeleteSubjectSet(ctx, req.(*DeleteSubjectSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_ListSubjectSets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSubjectSetsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).ListSubjectSets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_ListSubjectSets_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).ListSubjectSets(ctx, req.(*ListSubjectSetsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_MatchSubjectMappings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MatchSubjectMappingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).MatchSubjectMappings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_MatchSubjectMappings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).MatchSubjectMappings(ctx, req.(*MatchSubjectMappingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_ListSubjectMappings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSubjectMappingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).ListSubjectMappings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_ListSubjectMappings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).ListSubjectMappings(ctx, req.(*ListSubjectMappingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_GetSubjectMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSubjectMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).GetSubjectMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_GetSubjectMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).GetSubjectMapping(ctx, req.(*GetSubjectMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_CreateSubjectMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSubjectMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).CreateSubjectMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_CreateSubjectMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).CreateSubjectMapping(ctx, req.(*CreateSubjectMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_UpdateSubjectMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateSubjectMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).UpdateSubjectMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_UpdateSubjectMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).UpdateSubjectMapping(ctx, req.(*UpdateSubjectMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SubjectMappingService_DeleteSubjectMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSubjectMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SubjectMappingServiceServer).DeleteSubjectMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SubjectMappingService_DeleteSubjectMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SubjectMappingServiceServer).DeleteSubjectMapping(ctx, req.(*DeleteSubjectMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SubjectMappingService_ServiceDesc is the grpc.ServiceDesc for SubjectMappingService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SubjectMappingService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "subjectmapping.SubjectMappingService",
	HandlerType: (*SubjectMappingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetSubjectSet",
			Handler:    _SubjectMappingService_GetSubjectSet_Handler,
		},
		{
			MethodName: "CreateSubjectSet",
			Handler:    _SubjectMappingService_CreateSubjectSet_Handler,
		},
		{
			MethodName: "UpdateSubjectSet",
			Handler:    _SubjectMappingService_UpdateSubjectSet_Handler,
		},
		{
			MethodName: "DeleteSubjectSet",
			Handler:    _SubjectMappingService_DeleteSubjectSet_Handler,
		},
		{
			MethodName: "ListSubjectSets",
			Handler:    _SubjectMappingService_ListSubjectSets_Handler,
		},
		{
			MethodName: "MatchSubjectMappings",
			Handler:    _SubjectMappingService_MatchSubjectMappings_Handler,
		},
		{
			MethodName: "ListSubjectMappings",
			Handler:    _SubjectMappingService_ListSubjectMappings_Handler,
		},
		{
			MethodName: "GetSubjectMapping",
			Handler:    _SubjectMappingService_GetSubjectMapping_Handler,
		},
		{
			MethodName: "CreateSubjectMapping",
			Handler:    _SubjectMappingService_CreateSubjectMapping_Handler,
		},
		{
			MethodName: "UpdateSubjectMapping",
			Handler:    _SubjectMappingService_UpdateSubjectMapping_Handler,
		},
		{
			MethodName: "DeleteSubjectMapping",
			Handler:    _SubjectMappingService_DeleteSubjectMapping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "subjectmapping/subject_mapping.proto",
}
