// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: acse/v1/acse.proto

package acsev1

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	v11 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	v1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

type SubjectMapping_Operator int32

const (
	SubjectMapping_OPERATOR_UNSPECIFIED SubjectMapping_Operator = 0
	SubjectMapping_OPERATOR_IN          SubjectMapping_Operator = 1
	SubjectMapping_OPERATOR_NOT_IN      SubjectMapping_Operator = 2
)

// Enum value maps for SubjectMapping_Operator.
var (
	SubjectMapping_Operator_name = map[int32]string{
		0: "OPERATOR_UNSPECIFIED",
		1: "OPERATOR_IN",
		2: "OPERATOR_NOT_IN",
	}
	SubjectMapping_Operator_value = map[string]int32{
		"OPERATOR_UNSPECIFIED": 0,
		"OPERATOR_IN":          1,
		"OPERATOR_NOT_IN":      2,
	}
)

func (x SubjectMapping_Operator) Enum() *SubjectMapping_Operator {
	p := new(SubjectMapping_Operator)
	*p = x
	return p
}

func (x SubjectMapping_Operator) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SubjectMapping_Operator) Descriptor() protoreflect.EnumDescriptor {
	return file_acse_v1_acse_proto_enumTypes[0].Descriptor()
}

func (SubjectMapping_Operator) Type() protoreflect.EnumType {
	return &file_acse_v1_acse_proto_enumTypes[0]
}

func (x SubjectMapping_Operator) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SubjectMapping_Operator.Descriptor instead.
func (SubjectMapping_Operator) EnumDescriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{0, 0}
}

// *
// Define a mapping of an subject attribute to subject using a rule:
// <subject.subjectAttribute> <operator IN/NOT_IN> [subjectValue]
//
// Example subject mapping of a subject with nationality = CZE entitled to attribute relto:ZCE
// From Existing Policy: "http://demo.com/attr/relto/value/CZE": {"nationality": ["CZE"]}
// To Subject Mapping Policy:
// {
// attributeValueFQN: "http://demo.com/attr/relto/value/CZE"
// subjectAttribute: "nationality"
// subjectValues: ["CZE"]
// operator: "IN"
// }
type SubjectMapping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Descriptor_ *v1.ResourceDescriptor `protobuf:"bytes,1,opt,name=descriptor,proto3" json:"descriptor,omitempty"`
	// TODO should this be a list of values?
	// Attribute Value to be mapped to
	AttributeValueRef *v11.AttributeValueReference `protobuf:"bytes,2,opt,name=attribute_value_ref,json=attributeValueRef,proto3" json:"attribute_value_ref,omitempty"`
	// Resource Attribute Key; NOT Attribute Definition Attribute name
	SubjectAttribute string `protobuf:"bytes,3,opt,name=subject_attribute,json=subjectAttribute,proto3" json:"subject_attribute,omitempty"`
	// The list of comparison values for a resource's <attribute> value
	SubjectValues []string `protobuf:"bytes,4,rep,name=subject_values,json=subjectValues,proto3" json:"subject_values,omitempty"`
	// the operator
	Operator SubjectMapping_Operator `protobuf:"varint,5,opt,name=operator,proto3,enum=acse.v1.SubjectMapping_Operator" json:"operator,omitempty"`
}

func (x *SubjectMapping) Reset() {
	*x = SubjectMapping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubjectMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubjectMapping) ProtoMessage() {}

func (x *SubjectMapping) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubjectMapping.ProtoReflect.Descriptor instead.
func (*SubjectMapping) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{0}
}

func (x *SubjectMapping) GetDescriptor_() *v1.ResourceDescriptor {
	if x != nil {
		return x.Descriptor_
	}
	return nil
}

func (x *SubjectMapping) GetAttributeValueRef() *v11.AttributeValueReference {
	if x != nil {
		return x.AttributeValueRef
	}
	return nil
}

func (x *SubjectMapping) GetSubjectAttribute() string {
	if x != nil {
		return x.SubjectAttribute
	}
	return ""
}

func (x *SubjectMapping) GetSubjectValues() []string {
	if x != nil {
		return x.SubjectValues
	}
	return nil
}

func (x *SubjectMapping) GetOperator() SubjectMapping_Operator {
	if x != nil {
		return x.Operator
	}
	return SubjectMapping_OPERATOR_UNSPECIFIED
}

type GetSubjectMappingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id int32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetSubjectMappingRequest) Reset() {
	*x = GetSubjectMappingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSubjectMappingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSubjectMappingRequest) ProtoMessage() {}

func (x *GetSubjectMappingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSubjectMappingRequest.ProtoReflect.Descriptor instead.
func (*GetSubjectMappingRequest) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{1}
}

func (x *GetSubjectMappingRequest) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

type GetSubjectMappingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SubjectMapping *SubjectMapping `protobuf:"bytes,1,opt,name=subject_mapping,json=subjectMapping,proto3" json:"subject_mapping,omitempty"`
}

func (x *GetSubjectMappingResponse) Reset() {
	*x = GetSubjectMappingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSubjectMappingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSubjectMappingResponse) ProtoMessage() {}

func (x *GetSubjectMappingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSubjectMappingResponse.ProtoReflect.Descriptor instead.
func (*GetSubjectMappingResponse) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{2}
}

func (x *GetSubjectMappingResponse) GetSubjectMapping() *SubjectMapping {
	if x != nil {
		return x.SubjectMapping
	}
	return nil
}

type ListSubjectMappingsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Selector *v1.ResourceSelector `protobuf:"bytes,1,opt,name=selector,proto3" json:"selector,omitempty"`
}

func (x *ListSubjectMappingsRequest) Reset() {
	*x = ListSubjectMappingsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListSubjectMappingsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListSubjectMappingsRequest) ProtoMessage() {}

func (x *ListSubjectMappingsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListSubjectMappingsRequest.ProtoReflect.Descriptor instead.
func (*ListSubjectMappingsRequest) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{3}
}

func (x *ListSubjectMappingsRequest) GetSelector() *v1.ResourceSelector {
	if x != nil {
		return x.Selector
	}
	return nil
}

type ListSubjectMappingsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SubjectMappings []*SubjectMapping `protobuf:"bytes,1,rep,name=subject_mappings,json=subjectMappings,proto3" json:"subject_mappings,omitempty"`
}

func (x *ListSubjectMappingsResponse) Reset() {
	*x = ListSubjectMappingsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListSubjectMappingsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListSubjectMappingsResponse) ProtoMessage() {}

func (x *ListSubjectMappingsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListSubjectMappingsResponse.ProtoReflect.Descriptor instead.
func (*ListSubjectMappingsResponse) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{4}
}

func (x *ListSubjectMappingsResponse) GetSubjectMappings() []*SubjectMapping {
	if x != nil {
		return x.SubjectMappings
	}
	return nil
}

type CreateSubjectMappingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SubjectMapping *SubjectMapping `protobuf:"bytes,1,opt,name=subject_mapping,json=subjectMapping,proto3" json:"subject_mapping,omitempty"`
}

func (x *CreateSubjectMappingRequest) Reset() {
	*x = CreateSubjectMappingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSubjectMappingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSubjectMappingRequest) ProtoMessage() {}

func (x *CreateSubjectMappingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateSubjectMappingRequest.ProtoReflect.Descriptor instead.
func (*CreateSubjectMappingRequest) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{5}
}

func (x *CreateSubjectMappingRequest) GetSubjectMapping() *SubjectMapping {
	if x != nil {
		return x.SubjectMapping
	}
	return nil
}

type CreateSubjectMappingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CreateSubjectMappingResponse) Reset() {
	*x = CreateSubjectMappingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSubjectMappingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSubjectMappingResponse) ProtoMessage() {}

func (x *CreateSubjectMappingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateSubjectMappingResponse.ProtoReflect.Descriptor instead.
func (*CreateSubjectMappingResponse) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{6}
}

type UpdateSubjectMappingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id             int32           `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	SubjectMapping *SubjectMapping `protobuf:"bytes,2,opt,name=subject_mapping,json=subjectMapping,proto3" json:"subject_mapping,omitempty"`
}

func (x *UpdateSubjectMappingRequest) Reset() {
	*x = UpdateSubjectMappingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateSubjectMappingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateSubjectMappingRequest) ProtoMessage() {}

func (x *UpdateSubjectMappingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateSubjectMappingRequest.ProtoReflect.Descriptor instead.
func (*UpdateSubjectMappingRequest) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateSubjectMappingRequest) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *UpdateSubjectMappingRequest) GetSubjectMapping() *SubjectMapping {
	if x != nil {
		return x.SubjectMapping
	}
	return nil
}

type UpdateSubjectMappingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *UpdateSubjectMappingResponse) Reset() {
	*x = UpdateSubjectMappingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateSubjectMappingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateSubjectMappingResponse) ProtoMessage() {}

func (x *UpdateSubjectMappingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateSubjectMappingResponse.ProtoReflect.Descriptor instead.
func (*UpdateSubjectMappingResponse) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{8}
}

type DeleteSubjectMappingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id int32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DeleteSubjectMappingRequest) Reset() {
	*x = DeleteSubjectMappingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteSubjectMappingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteSubjectMappingRequest) ProtoMessage() {}

func (x *DeleteSubjectMappingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteSubjectMappingRequest.ProtoReflect.Descriptor instead.
func (*DeleteSubjectMappingRequest) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteSubjectMappingRequest) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

type DeleteSubjectMappingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteSubjectMappingResponse) Reset() {
	*x = DeleteSubjectMappingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_acse_v1_acse_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteSubjectMappingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteSubjectMappingResponse) ProtoMessage() {}

func (x *DeleteSubjectMappingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_acse_v1_acse_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteSubjectMappingResponse.ProtoReflect.Descriptor instead.
func (*DeleteSubjectMappingResponse) Descriptor() ([]byte, []int) {
	return file_acse_v1_acse_proto_rawDescGZIP(), []int{10}
}

var File_acse_v1_acse_proto protoreflect.FileDescriptor

var file_acse_v1_acse_proto_rawDesc = []byte{
	0x0a, 0x12, 0x61, 0x63, 0x73, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1e, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x62,
	0x75, 0x66, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x92, 0x03, 0x0a, 0x0e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x12, 0x3d, 0x0a, 0x0a, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x52, 0x0a, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x6f, 0x72, 0x12, 0x56, 0x0a, 0x13, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x5f,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x72, 0x65, 0x66, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x26, 0x2e, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65,
	0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x52, 0x11, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x66, 0x12, 0x2b, 0x0a, 0x11, 0x73, 0x75,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x74,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x73, 0x75, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0d, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x12, 0x49,
	0x0a, 0x08, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x20, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x2e, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74,
	0x6f, 0x72, 0x42, 0x0b, 0xba, 0x48, 0x08, 0xc8, 0x01, 0x01, 0x82, 0x01, 0x02, 0x10, 0x01, 0x52,
	0x08, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x22, 0x4a, 0x0a, 0x08, 0x4f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x18, 0x0a, 0x14, 0x4f, 0x50, 0x45, 0x52, 0x41, 0x54, 0x4f,
	0x52, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12,
	0x0f, 0x0a, 0x0b, 0x4f, 0x50, 0x45, 0x52, 0x41, 0x54, 0x4f, 0x52, 0x5f, 0x49, 0x4e, 0x10, 0x01,
	0x12, 0x13, 0x0a, 0x0f, 0x4f, 0x50, 0x45, 0x52, 0x41, 0x54, 0x4f, 0x52, 0x5f, 0x4e, 0x4f, 0x54,
	0x5f, 0x49, 0x4e, 0x10, 0x02, 0x22, 0x32, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x53, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x16, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x42, 0x06, 0xba,
	0x48, 0x03, 0xc8, 0x01, 0x01, 0x52, 0x02, 0x69, 0x64, 0x22, 0x5d, 0x0a, 0x19, 0x47, 0x65, 0x74,
	0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x40, 0x0a, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x17, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x0e, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x22, 0x55, 0x0a, 0x1a, 0x4c, 0x69, 0x73, 0x74,
	0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x37, 0x0a, 0x08, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x08, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x22,
	0x61, 0x0a, 0x1b, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x42,
	0x0a, 0x10, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e,
	0x67, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e,
	0x67, 0x52, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e,
	0x67, 0x73, 0x22, 0x67, 0x0a, 0x1b, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x48, 0x0a, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70,
	0x70, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x61, 0x63, 0x73,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x42, 0x06, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0x52, 0x0e, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x22, 0x1e, 0x0a, 0x1c, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x7f, 0x0a, 0x1b, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x42, 0x06, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x48, 0x0a, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x61, 0x63,
	0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70,
	0x70, 0x69, 0x6e, 0x67, 0x42, 0x06, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0x52, 0x0e, 0x73, 0x75,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x22, 0x1e, 0x0a, 0x1c,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70,
	0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x35, 0x0a, 0x1b,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70,
	0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x42, 0x06, 0xba, 0x48, 0x03, 0xc8, 0x01, 0x01, 0x52,
	0x02, 0x69, 0x64, 0x22, 0x1e, 0x0a, 0x1c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x32, 0xff, 0x05, 0x0a, 0x16, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x45,
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x87,
	0x01, 0x0a, 0x13, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x23, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x61, 0x63,
	0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x25, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1f, 0x12, 0x1d, 0x2f, 0x76, 0x31, 0x2f, 0x65,
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2f,
	0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x86, 0x01, 0x0a, 0x11, 0x47, 0x65, 0x74,
	0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x21,
	0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x22, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2a, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x24, 0x12, 0x22, 0x2f,
	0x76, 0x31, 0x2f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x73, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x2f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x7b, 0x69, 0x64,
	0x7d, 0x12, 0x9b, 0x01, 0x0a, 0x14, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x24, 0x2e, 0x61, 0x63, 0x73,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x25, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x36, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x30, 0x3a,
	0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67,
	0x22, 0x1d, 0x2f, 0x76, 0x31, 0x2f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x12,
	0xa0, 0x01, 0x0a, 0x14, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x24, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25,
	0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x3b, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x35, 0x3a, 0x0f, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x22, 0x22,
	0x2f, 0x76, 0x31, 0x2f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x2f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x7b, 0x69,
	0x64, 0x7d, 0x12, 0x90, 0x01, 0x0a, 0x14, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x24, 0x2e, 0x61, 0x63,
	0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x25, 0x2e, 0x61, 0x63, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2b, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x25,
	0x2a, 0x23, 0x2f, 0x76, 0x31, 0x2f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2f, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73,
	0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x42, 0x8b, 0x01, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x63,
	0x73, 0x65, 0x2e, 0x76, 0x31, 0x42, 0x09, 0x41, 0x63, 0x73, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f,
	0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2d, 0x76,
	0x32, 0x2d, 0x70, 0x6f, 0x63, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x63, 0x73, 0x65, 0x2f, 0x76,
	0x31, 0x3b, 0x61, 0x63, 0x73, 0x65, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x41, 0x58, 0x58, 0xaa, 0x02,
	0x07, 0x41, 0x63, 0x73, 0x65, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x07, 0x41, 0x63, 0x73, 0x65, 0x5c,
	0x56, 0x31, 0xe2, 0x02, 0x13, 0x41, 0x63, 0x73, 0x65, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x08, 0x41, 0x63, 0x73, 0x65, 0x3a,
	0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_acse_v1_acse_proto_rawDescOnce sync.Once
	file_acse_v1_acse_proto_rawDescData = file_acse_v1_acse_proto_rawDesc
)

func file_acse_v1_acse_proto_rawDescGZIP() []byte {
	file_acse_v1_acse_proto_rawDescOnce.Do(func() {
		file_acse_v1_acse_proto_rawDescData = protoimpl.X.CompressGZIP(file_acse_v1_acse_proto_rawDescData)
	})
	return file_acse_v1_acse_proto_rawDescData
}

var file_acse_v1_acse_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_acse_v1_acse_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_acse_v1_acse_proto_goTypes = []interface{}{
	(SubjectMapping_Operator)(0),         // 0: acse.v1.SubjectMapping.Operator
	(*SubjectMapping)(nil),               // 1: acse.v1.SubjectMapping
	(*GetSubjectMappingRequest)(nil),     // 2: acse.v1.GetSubjectMappingRequest
	(*GetSubjectMappingResponse)(nil),    // 3: acse.v1.GetSubjectMappingResponse
	(*ListSubjectMappingsRequest)(nil),   // 4: acse.v1.ListSubjectMappingsRequest
	(*ListSubjectMappingsResponse)(nil),  // 5: acse.v1.ListSubjectMappingsResponse
	(*CreateSubjectMappingRequest)(nil),  // 6: acse.v1.CreateSubjectMappingRequest
	(*CreateSubjectMappingResponse)(nil), // 7: acse.v1.CreateSubjectMappingResponse
	(*UpdateSubjectMappingRequest)(nil),  // 8: acse.v1.UpdateSubjectMappingRequest
	(*UpdateSubjectMappingResponse)(nil), // 9: acse.v1.UpdateSubjectMappingResponse
	(*DeleteSubjectMappingRequest)(nil),  // 10: acse.v1.DeleteSubjectMappingRequest
	(*DeleteSubjectMappingResponse)(nil), // 11: acse.v1.DeleteSubjectMappingResponse
	(*v1.ResourceDescriptor)(nil),        // 12: common.v1.ResourceDescriptor
	(*v11.AttributeValueReference)(nil),  // 13: attributes.v1.AttributeValueReference
	(*v1.ResourceSelector)(nil),          // 14: common.v1.ResourceSelector
}
var file_acse_v1_acse_proto_depIdxs = []int32{
	12, // 0: acse.v1.SubjectMapping.descriptor:type_name -> common.v1.ResourceDescriptor
	13, // 1: acse.v1.SubjectMapping.attribute_value_ref:type_name -> attributes.v1.AttributeValueReference
	0,  // 2: acse.v1.SubjectMapping.operator:type_name -> acse.v1.SubjectMapping.Operator
	1,  // 3: acse.v1.GetSubjectMappingResponse.subject_mapping:type_name -> acse.v1.SubjectMapping
	14, // 4: acse.v1.ListSubjectMappingsRequest.selector:type_name -> common.v1.ResourceSelector
	1,  // 5: acse.v1.ListSubjectMappingsResponse.subject_mappings:type_name -> acse.v1.SubjectMapping
	1,  // 6: acse.v1.CreateSubjectMappingRequest.subject_mapping:type_name -> acse.v1.SubjectMapping
	1,  // 7: acse.v1.UpdateSubjectMappingRequest.subject_mapping:type_name -> acse.v1.SubjectMapping
	4,  // 8: acse.v1.SubjectEncodingService.ListSubjectMappings:input_type -> acse.v1.ListSubjectMappingsRequest
	2,  // 9: acse.v1.SubjectEncodingService.GetSubjectMapping:input_type -> acse.v1.GetSubjectMappingRequest
	6,  // 10: acse.v1.SubjectEncodingService.CreateSubjectMapping:input_type -> acse.v1.CreateSubjectMappingRequest
	8,  // 11: acse.v1.SubjectEncodingService.UpdateSubjectMapping:input_type -> acse.v1.UpdateSubjectMappingRequest
	10, // 12: acse.v1.SubjectEncodingService.DeleteSubjectMapping:input_type -> acse.v1.DeleteSubjectMappingRequest
	5,  // 13: acse.v1.SubjectEncodingService.ListSubjectMappings:output_type -> acse.v1.ListSubjectMappingsResponse
	3,  // 14: acse.v1.SubjectEncodingService.GetSubjectMapping:output_type -> acse.v1.GetSubjectMappingResponse
	7,  // 15: acse.v1.SubjectEncodingService.CreateSubjectMapping:output_type -> acse.v1.CreateSubjectMappingResponse
	9,  // 16: acse.v1.SubjectEncodingService.UpdateSubjectMapping:output_type -> acse.v1.UpdateSubjectMappingResponse
	11, // 17: acse.v1.SubjectEncodingService.DeleteSubjectMapping:output_type -> acse.v1.DeleteSubjectMappingResponse
	13, // [13:18] is the sub-list for method output_type
	8,  // [8:13] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_acse_v1_acse_proto_init() }
func file_acse_v1_acse_proto_init() {
	if File_acse_v1_acse_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_acse_v1_acse_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubjectMapping); i {
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
		file_acse_v1_acse_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSubjectMappingRequest); i {
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
		file_acse_v1_acse_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSubjectMappingResponse); i {
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
		file_acse_v1_acse_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListSubjectMappingsRequest); i {
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
		file_acse_v1_acse_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListSubjectMappingsResponse); i {
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
		file_acse_v1_acse_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateSubjectMappingRequest); i {
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
		file_acse_v1_acse_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateSubjectMappingResponse); i {
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
		file_acse_v1_acse_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateSubjectMappingRequest); i {
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
		file_acse_v1_acse_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateSubjectMappingResponse); i {
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
		file_acse_v1_acse_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteSubjectMappingRequest); i {
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
		file_acse_v1_acse_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteSubjectMappingResponse); i {
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
			RawDescriptor: file_acse_v1_acse_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_acse_v1_acse_proto_goTypes,
		DependencyIndexes: file_acse_v1_acse_proto_depIdxs,
		EnumInfos:         file_acse_v1_acse_proto_enumTypes,
		MessageInfos:      file_acse_v1_acse_proto_msgTypes,
	}.Build()
	File_acse_v1_acse_proto = out.File
	file_acse_v1_acse_proto_rawDesc = nil
	file_acse_v1_acse_proto_goTypes = nil
	file_acse_v1_acse_proto_depIdxs = nil
}
