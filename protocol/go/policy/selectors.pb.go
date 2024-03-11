// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: policy/selectors.proto

package policy

import (
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

type AttributeNamespaceSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithAttributes *AttributeNamespaceSelector_AttributeSelector `protobuf:"bytes,10,opt,name=with_attributes,json=withAttributes,proto3" json:"with_attributes,omitempty"`
}

func (x *AttributeNamespaceSelector) Reset() {
	*x = AttributeNamespaceSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeNamespaceSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeNamespaceSelector) ProtoMessage() {}

func (x *AttributeNamespaceSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeNamespaceSelector.ProtoReflect.Descriptor instead.
func (*AttributeNamespaceSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{0}
}

func (x *AttributeNamespaceSelector) GetWithAttributes() *AttributeNamespaceSelector_AttributeSelector {
	if x != nil {
		return x.WithAttributes
	}
	return nil
}

type AttributeDefinitionSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithKeyAccessGrants bool                                           `protobuf:"varint,1,opt,name=with_key_access_grants,json=withKeyAccessGrants,proto3" json:"with_key_access_grants,omitempty"`
	WithNamespace       *AttributeDefinitionSelector_NamespaceSelector `protobuf:"bytes,10,opt,name=with_namespace,json=withNamespace,proto3" json:"with_namespace,omitempty"`
	WithValues          *AttributeDefinitionSelector_ValueSelector     `protobuf:"bytes,11,opt,name=with_values,json=withValues,proto3" json:"with_values,omitempty"`
}

func (x *AttributeDefinitionSelector) Reset() {
	*x = AttributeDefinitionSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeDefinitionSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeDefinitionSelector) ProtoMessage() {}

func (x *AttributeDefinitionSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeDefinitionSelector.ProtoReflect.Descriptor instead.
func (*AttributeDefinitionSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{1}
}

func (x *AttributeDefinitionSelector) GetWithKeyAccessGrants() bool {
	if x != nil {
		return x.WithKeyAccessGrants
	}
	return false
}

func (x *AttributeDefinitionSelector) GetWithNamespace() *AttributeDefinitionSelector_NamespaceSelector {
	if x != nil {
		return x.WithNamespace
	}
	return nil
}

func (x *AttributeDefinitionSelector) GetWithValues() *AttributeDefinitionSelector_ValueSelector {
	if x != nil {
		return x.WithValues
	}
	return nil
}

type AttributeValueSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithKeyAccessGrants bool                                      `protobuf:"varint,1,opt,name=with_key_access_grants,json=withKeyAccessGrants,proto3" json:"with_key_access_grants,omitempty"`
	WithSubjectMaps     bool                                      `protobuf:"varint,2,opt,name=with_subject_maps,json=withSubjectMaps,proto3" json:"with_subject_maps,omitempty"`
	WithResourceMaps    bool                                      `protobuf:"varint,3,opt,name=with_resource_maps,json=withResourceMaps,proto3" json:"with_resource_maps,omitempty"`
	WithAttribute       *AttributeValueSelector_AttributeSelector `protobuf:"bytes,10,opt,name=with_attribute,json=withAttribute,proto3" json:"with_attribute,omitempty"`
}

func (x *AttributeValueSelector) Reset() {
	*x = AttributeValueSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeValueSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeValueSelector) ProtoMessage() {}

func (x *AttributeValueSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeValueSelector.ProtoReflect.Descriptor instead.
func (*AttributeValueSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{2}
}

func (x *AttributeValueSelector) GetWithKeyAccessGrants() bool {
	if x != nil {
		return x.WithKeyAccessGrants
	}
	return false
}

func (x *AttributeValueSelector) GetWithSubjectMaps() bool {
	if x != nil {
		return x.WithSubjectMaps
	}
	return false
}

func (x *AttributeValueSelector) GetWithResourceMaps() bool {
	if x != nil {
		return x.WithResourceMaps
	}
	return false
}

func (x *AttributeValueSelector) GetWithAttribute() *AttributeValueSelector_AttributeSelector {
	if x != nil {
		return x.WithAttribute
	}
	return nil
}

type AttributeNamespaceSelector_AttributeSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithKeyAccessGrants bool                                                        `protobuf:"varint,1,opt,name=with_key_access_grants,json=withKeyAccessGrants,proto3" json:"with_key_access_grants,omitempty"`
	WithValues          *AttributeNamespaceSelector_AttributeSelector_ValueSelector `protobuf:"bytes,10,opt,name=with_values,json=withValues,proto3" json:"with_values,omitempty"`
}

func (x *AttributeNamespaceSelector_AttributeSelector) Reset() {
	*x = AttributeNamespaceSelector_AttributeSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeNamespaceSelector_AttributeSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeNamespaceSelector_AttributeSelector) ProtoMessage() {}

func (x *AttributeNamespaceSelector_AttributeSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeNamespaceSelector_AttributeSelector.ProtoReflect.Descriptor instead.
func (*AttributeNamespaceSelector_AttributeSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{0, 0}
}

func (x *AttributeNamespaceSelector_AttributeSelector) GetWithKeyAccessGrants() bool {
	if x != nil {
		return x.WithKeyAccessGrants
	}
	return false
}

func (x *AttributeNamespaceSelector_AttributeSelector) GetWithValues() *AttributeNamespaceSelector_AttributeSelector_ValueSelector {
	if x != nil {
		return x.WithValues
	}
	return nil
}

type AttributeNamespaceSelector_AttributeSelector_ValueSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithKeyAccessGrants bool `protobuf:"varint,1,opt,name=with_key_access_grants,json=withKeyAccessGrants,proto3" json:"with_key_access_grants,omitempty"`
	WithSubjectMaps     bool `protobuf:"varint,2,opt,name=with_subject_maps,json=withSubjectMaps,proto3" json:"with_subject_maps,omitempty"`
	WithResourceMaps    bool `protobuf:"varint,3,opt,name=with_resource_maps,json=withResourceMaps,proto3" json:"with_resource_maps,omitempty"`
}

func (x *AttributeNamespaceSelector_AttributeSelector_ValueSelector) Reset() {
	*x = AttributeNamespaceSelector_AttributeSelector_ValueSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeNamespaceSelector_AttributeSelector_ValueSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeNamespaceSelector_AttributeSelector_ValueSelector) ProtoMessage() {}

func (x *AttributeNamespaceSelector_AttributeSelector_ValueSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeNamespaceSelector_AttributeSelector_ValueSelector.ProtoReflect.Descriptor instead.
func (*AttributeNamespaceSelector_AttributeSelector_ValueSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{0, 0, 0}
}

func (x *AttributeNamespaceSelector_AttributeSelector_ValueSelector) GetWithKeyAccessGrants() bool {
	if x != nil {
		return x.WithKeyAccessGrants
	}
	return false
}

func (x *AttributeNamespaceSelector_AttributeSelector_ValueSelector) GetWithSubjectMaps() bool {
	if x != nil {
		return x.WithSubjectMaps
	}
	return false
}

func (x *AttributeNamespaceSelector_AttributeSelector_ValueSelector) GetWithResourceMaps() bool {
	if x != nil {
		return x.WithResourceMaps
	}
	return false
}

type AttributeDefinitionSelector_NamespaceSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *AttributeDefinitionSelector_NamespaceSelector) Reset() {
	*x = AttributeDefinitionSelector_NamespaceSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeDefinitionSelector_NamespaceSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeDefinitionSelector_NamespaceSelector) ProtoMessage() {}

func (x *AttributeDefinitionSelector_NamespaceSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeDefinitionSelector_NamespaceSelector.ProtoReflect.Descriptor instead.
func (*AttributeDefinitionSelector_NamespaceSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{1, 0}
}

type AttributeDefinitionSelector_ValueSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithKeyAccessGrants bool `protobuf:"varint,1,opt,name=with_key_access_grants,json=withKeyAccessGrants,proto3" json:"with_key_access_grants,omitempty"`
	WithSubjectMaps     bool `protobuf:"varint,2,opt,name=with_subject_maps,json=withSubjectMaps,proto3" json:"with_subject_maps,omitempty"`
	WithResourceMaps    bool `protobuf:"varint,3,opt,name=with_resource_maps,json=withResourceMaps,proto3" json:"with_resource_maps,omitempty"`
}

func (x *AttributeDefinitionSelector_ValueSelector) Reset() {
	*x = AttributeDefinitionSelector_ValueSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeDefinitionSelector_ValueSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeDefinitionSelector_ValueSelector) ProtoMessage() {}

func (x *AttributeDefinitionSelector_ValueSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeDefinitionSelector_ValueSelector.ProtoReflect.Descriptor instead.
func (*AttributeDefinitionSelector_ValueSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{1, 1}
}

func (x *AttributeDefinitionSelector_ValueSelector) GetWithKeyAccessGrants() bool {
	if x != nil {
		return x.WithKeyAccessGrants
	}
	return false
}

func (x *AttributeDefinitionSelector_ValueSelector) GetWithSubjectMaps() bool {
	if x != nil {
		return x.WithSubjectMaps
	}
	return false
}

func (x *AttributeDefinitionSelector_ValueSelector) GetWithResourceMaps() bool {
	if x != nil {
		return x.WithResourceMaps
	}
	return false
}

type AttributeValueSelector_AttributeSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WithKeyAccessGrants bool                                                        `protobuf:"varint,1,opt,name=with_key_access_grants,json=withKeyAccessGrants,proto3" json:"with_key_access_grants,omitempty"`
	WithNamespace       *AttributeValueSelector_AttributeSelector_NamespaceSelector `protobuf:"bytes,10,opt,name=with_namespace,json=withNamespace,proto3" json:"with_namespace,omitempty"`
}

func (x *AttributeValueSelector_AttributeSelector) Reset() {
	*x = AttributeValueSelector_AttributeSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeValueSelector_AttributeSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeValueSelector_AttributeSelector) ProtoMessage() {}

func (x *AttributeValueSelector_AttributeSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeValueSelector_AttributeSelector.ProtoReflect.Descriptor instead.
func (*AttributeValueSelector_AttributeSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{2, 0}
}

func (x *AttributeValueSelector_AttributeSelector) GetWithKeyAccessGrants() bool {
	if x != nil {
		return x.WithKeyAccessGrants
	}
	return false
}

func (x *AttributeValueSelector_AttributeSelector) GetWithNamespace() *AttributeValueSelector_AttributeSelector_NamespaceSelector {
	if x != nil {
		return x.WithNamespace
	}
	return nil
}

type AttributeValueSelector_AttributeSelector_NamespaceSelector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *AttributeValueSelector_AttributeSelector_NamespaceSelector) Reset() {
	*x = AttributeValueSelector_AttributeSelector_NamespaceSelector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_policy_selectors_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttributeValueSelector_AttributeSelector_NamespaceSelector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttributeValueSelector_AttributeSelector_NamespaceSelector) ProtoMessage() {}

func (x *AttributeValueSelector_AttributeSelector_NamespaceSelector) ProtoReflect() protoreflect.Message {
	mi := &file_policy_selectors_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttributeValueSelector_AttributeSelector_NamespaceSelector.ProtoReflect.Descriptor instead.
func (*AttributeValueSelector_AttributeSelector_NamespaceSelector) Descriptor() ([]byte, []int) {
	return file_policy_selectors_proto_rawDescGZIP(), []int{2, 0, 0}
}

var File_policy_selectors_proto protoreflect.FileDescriptor

var file_policy_selectors_proto_rawDesc = []byte{
	0x0a, 0x16, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2f, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x22, 0xcc, 0x03, 0x0a, 0x1a, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x4e, 0x61,
	0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12,
	0x5d, 0x0a, 0x0f, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x34, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x41, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x0e,
	0x77, 0x69, 0x74, 0x68, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x1a, 0xce,
	0x02, 0x0a, 0x11, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x53, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x12, 0x33, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79,
	0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x77, 0x69, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x12, 0x63, 0x0a, 0x0b, 0x77, 0x69, 0x74,
	0x68, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x42,
	0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x53, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x52, 0x0a, 0x77, 0x69, 0x74, 0x68, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x1a, 0x9e,
	0x01, 0x0a, 0x0d, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x12, 0x33, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x13, 0x77, 0x69, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x47,
	0x72, 0x61, 0x6e, 0x74, 0x73, 0x12, 0x2a, 0x0a, 0x11, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x73, 0x75,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0f, 0x77, 0x69, 0x74, 0x68, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70,
	0x73, 0x12, 0x2c, 0x0a, 0x12, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x77,
	0x69, 0x74, 0x68, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x70, 0x73, 0x22,
	0xba, 0x03, 0x0a, 0x1b, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x44, 0x65, 0x66,
	0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12,
	0x33, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x13, 0x77, 0x69, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x47, 0x72,
	0x61, 0x6e, 0x74, 0x73, 0x12, 0x5c, 0x0a, 0x0e, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x44,
	0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x2e, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x52, 0x0d, 0x77, 0x69, 0x74, 0x68, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x12, 0x52, 0x0a, 0x0b, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69,
	0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x0a, 0x77, 0x69, 0x74, 0x68,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x1a, 0x13, 0x0a, 0x11, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x1a, 0x9e, 0x01, 0x0a, 0x0d,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x33, 0x0a,
	0x16, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x77,
	0x69, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x47, 0x72, 0x61, 0x6e,
	0x74, 0x73, 0x12, 0x2a, 0x0a, 0x11, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x73, 0x75, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x77,
	0x69, 0x74, 0x68, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x73, 0x12, 0x2c,
	0x0a, 0x12, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f,
	0x6d, 0x61, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x77, 0x69, 0x74, 0x68,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x70, 0x73, 0x22, 0xcb, 0x03, 0x0a,
	0x16, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x53,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x33, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x5f,
	0x6b, 0x65, 0x79, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x77, 0x69, 0x74, 0x68, 0x4b, 0x65, 0x79,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x12, 0x2a, 0x0a, 0x11,
	0x77, 0x69, 0x74, 0x68, 0x5f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x61, 0x70,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x77, 0x69, 0x74, 0x68, 0x53, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x70, 0x73, 0x12, 0x2c, 0x0a, 0x12, 0x77, 0x69, 0x74, 0x68,
	0x5f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x73, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x77, 0x69, 0x74, 0x68, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x4d, 0x61, 0x70, 0x73, 0x12, 0x57, 0x0a, 0x0e, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30,
	0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x41,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x52, 0x0d, 0x77, 0x69, 0x74, 0x68, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x1a,
	0xc8, 0x01, 0x0a, 0x11, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x33, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6b, 0x65,
	0x79, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x77, 0x69, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x12, 0x69, 0x0a, 0x0e, 0x77, 0x69,
	0x74, 0x68, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x42, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x41, 0x74, 0x74, 0x72,
	0x69, 0x62, 0x75, 0x74, 0x65, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x2e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x53, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x2e, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x53, 0x65,
	0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x0d, 0x77, 0x69, 0x74, 0x68, 0x4e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x1a, 0x13, 0x0a, 0x11, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x42, 0x94, 0x01, 0x0a, 0x1a, 0x69,
	0x6f, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f,
	0x72, 0x6d, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x42, 0x0e, 0x53, 0x65, 0x6c, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2e, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2f,
	0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
	0x6c, 0x2f, 0x67, 0x6f, 0x2f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xa2, 0x02, 0x03, 0x50, 0x58,
	0x58, 0xaa, 0x02, 0x06, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xca, 0x02, 0x06, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0xe2, 0x02, 0x12, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5c, 0x47, 0x50, 0x42,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x06, 0x50, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_policy_selectors_proto_rawDescOnce sync.Once
	file_policy_selectors_proto_rawDescData = file_policy_selectors_proto_rawDesc
)

func file_policy_selectors_proto_rawDescGZIP() []byte {
	file_policy_selectors_proto_rawDescOnce.Do(func() {
		file_policy_selectors_proto_rawDescData = protoimpl.X.CompressGZIP(file_policy_selectors_proto_rawDescData)
	})
	return file_policy_selectors_proto_rawDescData
}

var file_policy_selectors_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_policy_selectors_proto_goTypes = []interface{}{
	(*AttributeNamespaceSelector)(nil),                                 // 0: policy.AttributeNamespaceSelector
	(*AttributeDefinitionSelector)(nil),                                // 1: policy.AttributeDefinitionSelector
	(*AttributeValueSelector)(nil),                                     // 2: policy.AttributeValueSelector
	(*AttributeNamespaceSelector_AttributeSelector)(nil),               // 3: policy.AttributeNamespaceSelector.AttributeSelector
	(*AttributeNamespaceSelector_AttributeSelector_ValueSelector)(nil), // 4: policy.AttributeNamespaceSelector.AttributeSelector.ValueSelector
	(*AttributeDefinitionSelector_NamespaceSelector)(nil),              // 5: policy.AttributeDefinitionSelector.NamespaceSelector
	(*AttributeDefinitionSelector_ValueSelector)(nil),                  // 6: policy.AttributeDefinitionSelector.ValueSelector
	(*AttributeValueSelector_AttributeSelector)(nil),                   // 7: policy.AttributeValueSelector.AttributeSelector
	(*AttributeValueSelector_AttributeSelector_NamespaceSelector)(nil), // 8: policy.AttributeValueSelector.AttributeSelector.NamespaceSelector
}
var file_policy_selectors_proto_depIdxs = []int32{
	3, // 0: policy.AttributeNamespaceSelector.with_attributes:type_name -> policy.AttributeNamespaceSelector.AttributeSelector
	5, // 1: policy.AttributeDefinitionSelector.with_namespace:type_name -> policy.AttributeDefinitionSelector.NamespaceSelector
	6, // 2: policy.AttributeDefinitionSelector.with_values:type_name -> policy.AttributeDefinitionSelector.ValueSelector
	7, // 3: policy.AttributeValueSelector.with_attribute:type_name -> policy.AttributeValueSelector.AttributeSelector
	4, // 4: policy.AttributeNamespaceSelector.AttributeSelector.with_values:type_name -> policy.AttributeNamespaceSelector.AttributeSelector.ValueSelector
	8, // 5: policy.AttributeValueSelector.AttributeSelector.with_namespace:type_name -> policy.AttributeValueSelector.AttributeSelector.NamespaceSelector
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_policy_selectors_proto_init() }
func file_policy_selectors_proto_init() {
	if File_policy_selectors_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_policy_selectors_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeNamespaceSelector); i {
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
		file_policy_selectors_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeDefinitionSelector); i {
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
		file_policy_selectors_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeValueSelector); i {
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
		file_policy_selectors_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeNamespaceSelector_AttributeSelector); i {
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
		file_policy_selectors_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeNamespaceSelector_AttributeSelector_ValueSelector); i {
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
		file_policy_selectors_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeDefinitionSelector_NamespaceSelector); i {
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
		file_policy_selectors_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeDefinitionSelector_ValueSelector); i {
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
		file_policy_selectors_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeValueSelector_AttributeSelector); i {
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
		file_policy_selectors_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttributeValueSelector_AttributeSelector_NamespaceSelector); i {
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
			RawDescriptor: file_policy_selectors_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_policy_selectors_proto_goTypes,
		DependencyIndexes: file_policy_selectors_proto_depIdxs,
		MessageInfos:      file_policy_selectors_proto_msgTypes,
	}.Build()
	File_policy_selectors_proto = out.File
	file_policy_selectors_proto_rawDesc = nil
	file_policy_selectors_proto_goTypes = nil
	file_policy_selectors_proto_depIdxs = nil
}
