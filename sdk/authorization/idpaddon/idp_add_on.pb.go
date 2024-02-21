// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: authorization/idpaddon/idp_add_on.proto

package idpaddon

import (
	entity "github.com/opentdf/platform/sdk/entity"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Example: Get idp attributes for bob and alice (both represented using an email address
// {
// "entities": [
// {
// "id": "e1",
// "emailAddress": "bob@example.org"
// },
// {
// "id": "e2",
// "emailAddress": "alice@example.org"
// }
// ]
// }
type IdpAddOnRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Entities []*entity.Entity `protobuf:"bytes,1,rep,name=entities,proto3" json:"entities,omitempty"`
}

func (x *IdpAddOnRequest) Reset() {
	*x = IdpAddOnRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authorization_idpaddon_idp_add_on_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdpAddOnRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdpAddOnRequest) ProtoMessage() {}

func (x *IdpAddOnRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authorization_idpaddon_idp_add_on_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdpAddOnRequest.ProtoReflect.Descriptor instead.
func (*IdpAddOnRequest) Descriptor() ([]byte, []int) {
	return file_authorization_idpaddon_idp_add_on_proto_rawDescGZIP(), []int{0}
}

func (x *IdpAddOnRequest) GetEntities() []*entity.Entity {
	if x != nil {
		return x.Entities
	}
	return nil
}

type IdpEntityRepresentation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AdditionalProps map[string]string `protobuf:"bytes,1,rep,name=additional_props,json=additionalProps,proto3" json:"additional_props,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Entity          *entity.Entity    `protobuf:"bytes,2,opt,name=entity,proto3" json:"entity,omitempty"`
}

func (x *IdpEntityRepresentation) Reset() {
	*x = IdpEntityRepresentation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authorization_idpaddon_idp_add_on_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdpEntityRepresentation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdpEntityRepresentation) ProtoMessage() {}

func (x *IdpEntityRepresentation) ProtoReflect() protoreflect.Message {
	mi := &file_authorization_idpaddon_idp_add_on_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdpEntityRepresentation.ProtoReflect.Descriptor instead.
func (*IdpEntityRepresentation) Descriptor() ([]byte, []int) {
	return file_authorization_idpaddon_idp_add_on_proto_rawDescGZIP(), []int{1}
}

func (x *IdpEntityRepresentation) GetAdditionalProps() map[string]string {
	if x != nil {
		return x.AdditionalProps
	}
	return nil
}

func (x *IdpEntityRepresentation) GetEntity() *entity.Entity {
	if x != nil {
		return x.Entity
	}
	return nil
}

type IdpAddOnResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EntityRepresentations []*IdpEntityRepresentation `protobuf:"bytes,1,rep,name=entity_representations,json=entityRepresentations,proto3" json:"entity_representations,omitempty"`
}

func (x *IdpAddOnResponse) Reset() {
	*x = IdpAddOnResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authorization_idpaddon_idp_add_on_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdpAddOnResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdpAddOnResponse) ProtoMessage() {}

func (x *IdpAddOnResponse) ProtoReflect() protoreflect.Message {
	mi := &file_authorization_idpaddon_idp_add_on_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdpAddOnResponse.ProtoReflect.Descriptor instead.
func (*IdpAddOnResponse) Descriptor() ([]byte, []int) {
	return file_authorization_idpaddon_idp_add_on_proto_rawDescGZIP(), []int{2}
}

func (x *IdpAddOnResponse) GetEntityRepresentations() []*IdpEntityRepresentation {
	if x != nil {
		return x.EntityRepresentations
	}
	return nil
}

var File_authorization_idpaddon_idp_add_on_proto protoreflect.FileDescriptor

var file_authorization_idpaddon_idp_add_on_proto_rawDesc = []byte{
	0x0a, 0x27, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f,
	0x69, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f, 0x6e, 0x2f, 0x69, 0x64, 0x70, 0x5f, 0x61, 0x64, 0x64,
	0x5f, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x61, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x69, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f,
	0x6e, 0x1a, 0x13, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3d, 0x0a, 0x0f, 0x49, 0x64, 0x70, 0x41, 0x64, 0x64,
	0x4f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2a, 0x0a, 0x08, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x69, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x2e, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x08, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x69, 0x65, 0x73, 0x22, 0xf6, 0x01, 0x0a, 0x17, 0x49, 0x64, 0x70, 0x45, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x52, 0x65, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x6f, 0x0a, 0x10, 0x61, 0x64, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f,
	0x70, 0x72, 0x6f, 0x70, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x44, 0x2e, 0x61, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x69, 0x64, 0x70, 0x61,
	0x64, 0x64, 0x6f, 0x6e, 0x2e, 0x49, 0x64, 0x70, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65,
	0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x41, 0x64, 0x64,
	0x69, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x50, 0x72, 0x6f, 0x70, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x0f, 0x61, 0x64, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x50, 0x72, 0x6f,
	0x70, 0x73, 0x12, 0x26, 0x0a, 0x06, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x45, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x52, 0x06, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x1a, 0x42, 0x0a, 0x14, 0x41, 0x64,
	0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x50, 0x72, 0x6f, 0x70, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x7a,
	0x0a, 0x10, 0x49, 0x64, 0x70, 0x41, 0x64, 0x64, 0x4f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x66, 0x0a, 0x16, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x72, 0x65, 0x70,
	0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2e, 0x69, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f, 0x6e, 0x2e, 0x49, 0x64, 0x70, 0x45,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x15, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x70, 0x72, 0x65,
	0x73, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x42, 0xdc, 0x01, 0x0a, 0x1a, 0x63,
	0x6f, 0x6d, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x69, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f, 0x6e, 0x42, 0x0d, 0x49, 0x64, 0x70, 0x41, 0x64,
	0x64, 0x4f, 0x6e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2f, 0x70,
	0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x73, 0x64, 0x6b, 0x2f, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x64, 0x70, 0x61, 0x64, 0x64,
	0x6f, 0x6e, 0xa2, 0x02, 0x03, 0x41, 0x49, 0x58, 0xaa, 0x02, 0x16, 0x41, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x49, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f,
	0x6e, 0xca, 0x02, 0x16, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x5c, 0x49, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f, 0x6e, 0xe2, 0x02, 0x22, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5c, 0x49, 0x64, 0x70, 0x61, 0x64,
	0x64, 0x6f, 0x6e, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea,
	0x02, 0x17, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a,
	0x3a, 0x49, 0x64, 0x70, 0x61, 0x64, 0x64, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_authorization_idpaddon_idp_add_on_proto_rawDescOnce sync.Once
	file_authorization_idpaddon_idp_add_on_proto_rawDescData = file_authorization_idpaddon_idp_add_on_proto_rawDesc
)

func file_authorization_idpaddon_idp_add_on_proto_rawDescGZIP() []byte {
	file_authorization_idpaddon_idp_add_on_proto_rawDescOnce.Do(func() {
		file_authorization_idpaddon_idp_add_on_proto_rawDescData = protoimpl.X.CompressGZIP(file_authorization_idpaddon_idp_add_on_proto_rawDescData)
	})
	return file_authorization_idpaddon_idp_add_on_proto_rawDescData
}

var file_authorization_idpaddon_idp_add_on_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_authorization_idpaddon_idp_add_on_proto_goTypes = []interface{}{
	(*IdpAddOnRequest)(nil),         // 0: authorization.idpaddon.IdpAddOnRequest
	(*IdpEntityRepresentation)(nil), // 1: authorization.idpaddon.IdpEntityRepresentation
	(*IdpAddOnResponse)(nil),        // 2: authorization.idpaddon.IdpAddOnResponse
	nil,                             // 3: authorization.idpaddon.IdpEntityRepresentation.AdditionalPropsEntry
	(*entity.Entity)(nil),           // 4: entity.Entity
}
var file_authorization_idpaddon_idp_add_on_proto_depIdxs = []int32{
	4, // 0: authorization.idpaddon.IdpAddOnRequest.entities:type_name -> entity.Entity
	3, // 1: authorization.idpaddon.IdpEntityRepresentation.additional_props:type_name -> authorization.idpaddon.IdpEntityRepresentation.AdditionalPropsEntry
	4, // 2: authorization.idpaddon.IdpEntityRepresentation.entity:type_name -> entity.Entity
	1, // 3: authorization.idpaddon.IdpAddOnResponse.entity_representations:type_name -> authorization.idpaddon.IdpEntityRepresentation
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_authorization_idpaddon_idp_add_on_proto_init() }
func file_authorization_idpaddon_idp_add_on_proto_init() {
	if File_authorization_idpaddon_idp_add_on_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_authorization_idpaddon_idp_add_on_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdpAddOnRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_authorization_idpaddon_idp_add_on_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdpEntityRepresentation); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_authorization_idpaddon_idp_add_on_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdpAddOnResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_authorization_idpaddon_idp_add_on_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_authorization_idpaddon_idp_add_on_proto_goTypes,
		DependencyIndexes: file_authorization_idpaddon_idp_add_on_proto_depIdxs,
		MessageInfos:      file_authorization_idpaddon_idp_add_on_proto_msgTypes,
	}.Build()
	File_authorization_idpaddon_idp_add_on_proto = out.File
	file_authorization_idpaddon_idp_add_on_proto_rawDesc = nil
	file_authorization_idpaddon_idp_add_on_proto_goTypes = nil
	file_authorization_idpaddon_idp_add_on_proto_depIdxs = nil
}
