// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: kas/kas.proto

package kas

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type InfoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *InfoRequest) Reset() {
	*x = InfoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InfoRequest) ProtoMessage() {}

func (x *InfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InfoRequest.ProtoReflect.Descriptor instead.
func (*InfoRequest) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{0}
}

// Service application level metadata
type InfoResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *InfoResponse) Reset() {
	*x = InfoResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InfoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InfoResponse) ProtoMessage() {}

func (x *InfoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InfoResponse.ProtoReflect.Descriptor instead.
func (*InfoResponse) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{1}
}

func (x *InfoResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type LegacyPublicKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Algorithm string `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
}

func (x *LegacyPublicKeyRequest) Reset() {
	*x = LegacyPublicKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LegacyPublicKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LegacyPublicKeyRequest) ProtoMessage() {}

func (x *LegacyPublicKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LegacyPublicKeyRequest.ProtoReflect.Descriptor instead.
func (*LegacyPublicKeyRequest) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{2}
}

func (x *LegacyPublicKeyRequest) GetAlgorithm() string {
	if x != nil {
		return x.Algorithm
	}
	return ""
}

type PublicKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Algorithm string `protobuf:"bytes,1,opt,name=algorithm,proto3" json:"algorithm,omitempty"`
	Fmt       string `protobuf:"bytes,2,opt,name=fmt,proto3" json:"fmt,omitempty"`
	V         string `protobuf:"bytes,3,opt,name=v,proto3" json:"v,omitempty"`
}

func (x *PublicKeyRequest) Reset() {
	*x = PublicKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeyRequest) ProtoMessage() {}

func (x *PublicKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeyRequest.ProtoReflect.Descriptor instead.
func (*PublicKeyRequest) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{3}
}

func (x *PublicKeyRequest) GetAlgorithm() string {
	if x != nil {
		return x.Algorithm
	}
	return ""
}

func (x *PublicKeyRequest) GetFmt() string {
	if x != nil {
		return x.Fmt
	}
	return ""
}

func (x *PublicKeyRequest) GetV() string {
	if x != nil {
		return x.V
	}
	return ""
}

type PublicKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicKey string `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *PublicKeyResponse) Reset() {
	*x = PublicKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeyResponse) ProtoMessage() {}

func (x *PublicKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeyResponse.ProtoReflect.Descriptor instead.
func (*PublicKeyResponse) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{4}
}

func (x *PublicKeyResponse) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type RewrapRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SignedRequestToken string `protobuf:"bytes,1,opt,name=signed_request_token,json=signedRequestToken,proto3" json:"signed_request_token,omitempty"`
	Bearer             string `protobuf:"bytes,2,opt,name=bearer,proto3" json:"bearer,omitempty"`
}

func (x *RewrapRequest) Reset() {
	*x = RewrapRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RewrapRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RewrapRequest) ProtoMessage() {}

func (x *RewrapRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RewrapRequest.ProtoReflect.Descriptor instead.
func (*RewrapRequest) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{5}
}

func (x *RewrapRequest) GetSignedRequestToken() string {
	if x != nil {
		return x.SignedRequestToken
	}
	return ""
}

func (x *RewrapRequest) GetBearer() string {
	if x != nil {
		return x.Bearer
	}
	return ""
}

type RewrapResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata         map[string]*structpb.Value `protobuf:"bytes,1,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	EntityWrappedKey []byte                     `protobuf:"bytes,2,opt,name=entity_wrapped_key,json=entityWrappedKey,proto3" json:"entity_wrapped_key,omitempty"`
	SessionPublicKey string                     `protobuf:"bytes,3,opt,name=session_public_key,json=sessionPublicKey,proto3" json:"session_public_key,omitempty"`
	SchemaVersion    string                     `protobuf:"bytes,4,opt,name=schema_version,json=schemaVersion,proto3" json:"schema_version,omitempty"`
}

func (x *RewrapResponse) Reset() {
	*x = RewrapResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kas_kas_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RewrapResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RewrapResponse) ProtoMessage() {}

func (x *RewrapResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kas_kas_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RewrapResponse.ProtoReflect.Descriptor instead.
func (*RewrapResponse) Descriptor() ([]byte, []int) {
	return file_kas_kas_proto_rawDescGZIP(), []int{6}
}

func (x *RewrapResponse) GetMetadata() map[string]*structpb.Value {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *RewrapResponse) GetEntityWrappedKey() []byte {
	if x != nil {
		return x.EntityWrappedKey
	}
	return nil
}

func (x *RewrapResponse) GetSessionPublicKey() string {
	if x != nil {
		return x.SessionPublicKey
	}
	return ""
}

func (x *RewrapResponse) GetSchemaVersion() string {
	if x != nil {
		return x.SchemaVersion
	}
	return ""
}

var File_kas_kas_proto protoreflect.FileDescriptor

var file_kas_kas_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6b, 0x61, 0x73, 0x2f, 0x6b, 0x61, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x03, 0x6b, 0x61, 0x73, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65,
	0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x0d, 0x0a, 0x0b, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22,
	0x28, 0x0a, 0x0c, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x36, 0x0a, 0x16, 0x4c, 0x65, 0x67,
	0x61, 0x63, 0x79, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x22, 0x6c, 0x0a, 0x10, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
	0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69,
	0x74, 0x68, 0x6d, 0x12, 0x1e, 0x0a, 0x03, 0x66, 0x6d, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x0c, 0x92, 0x41, 0x09, 0x32, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x03,
	0x66, 0x6d, 0x74, 0x12, 0x1a, 0x0a, 0x01, 0x76, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0c,
	0x92, 0x41, 0x09, 0x32, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x01, 0x76, 0x22,
	0x32, 0x0a, 0x11, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x22, 0x59, 0x0a, 0x0d, 0x52, 0x65, 0x77, 0x72, 0x61, 0x70, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x30, 0x0a, 0x14, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x62, 0x65, 0x61, 0x72, 0x65, 0x72,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x62, 0x65, 0x61, 0x72, 0x65, 0x72, 0x22, 0xa7,
	0x02, 0x0a, 0x0e, 0x52, 0x65, 0x77, 0x72, 0x61, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x3d, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x6b, 0x61, 0x73, 0x2e, 0x52, 0x65, 0x77, 0x72, 0x61, 0x70,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x12, 0x2c, 0x0a, 0x12, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x77, 0x72, 0x61, 0x70, 0x70,
	0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x12, 0x2c,
	0x0a, 0x12, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x25, 0x0a, 0x0e,
	0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x1a, 0x53, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2c, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x32, 0x8f, 0x03, 0x0a, 0x0d, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x45, 0x0a, 0x04, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x10, 0x2e, 0x6b, 0x61, 0x73, 0x2e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x11, 0x2e, 0x6b, 0x61, 0x73, 0x2e, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x18, 0x92, 0x41, 0x09, 0x4a, 0x07, 0x0a, 0x03,
	0x32, 0x30, 0x30, 0x12, 0x00, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x06, 0x12, 0x04, 0x2f, 0x6b, 0x61,
	0x73, 0x12, 0x66, 0x0a, 0x09, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x15,
	0x2e, 0x6b, 0x61, 0x73, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x6b, 0x61, 0x73, 0x2e, 0x50, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2a, 0x92,
	0x41, 0x09, 0x4a, 0x07, 0x0a, 0x03, 0x32, 0x30, 0x30, 0x12, 0x00, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x18, 0x12, 0x16, 0x2f, 0x6b, 0x61, 0x73, 0x2f, 0x76, 0x32, 0x2f, 0x6b, 0x61, 0x73, 0x5f, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x75, 0x0a, 0x0f, 0x4c, 0x65, 0x67,
	0x61, 0x63, 0x79, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x1b, 0x2e, 0x6b,
	0x61, 0x73, 0x2e, 0x4c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x27, 0x92, 0x41, 0x09, 0x4a, 0x07, 0x0a, 0x03,
	0x32, 0x30, 0x30, 0x12, 0x00, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x15, 0x12, 0x13, 0x2f, 0x6b, 0x61,
	0x73, 0x2f, 0x6b, 0x61, 0x73, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79,
	0x12, 0x58, 0x0a, 0x06, 0x52, 0x65, 0x77, 0x72, 0x61, 0x70, 0x12, 0x12, 0x2e, 0x6b, 0x61, 0x73,
	0x2e, 0x52, 0x65, 0x77, 0x72, 0x61, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13,
	0x2e, 0x6b, 0x61, 0x73, 0x2e, 0x52, 0x65, 0x77, 0x72, 0x61, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x25, 0x92, 0x41, 0x09, 0x4a, 0x07, 0x0a, 0x03, 0x32, 0x30, 0x30, 0x12,
	0x00, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x13, 0x3a, 0x01, 0x2a, 0x22, 0x0e, 0x2f, 0x6b, 0x61, 0x73,
	0x2f, 0x76, 0x32, 0x2f, 0x72, 0x65, 0x77, 0x72, 0x61, 0x70, 0x42, 0xe2, 0x01, 0x92, 0x41, 0x73,
	0x12, 0x71, 0x0a, 0x1a, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x44, 0x46, 0x20, 0x4b, 0x65, 0x79, 0x20,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2a, 0x4c,
	0x0a, 0x12, 0x42, 0x53, 0x44, 0x20, 0x33, 0x2d, 0x43, 0x6c, 0x61, 0x75, 0x73, 0x65, 0x20, 0x43,
	0x6c, 0x65, 0x61, 0x72, 0x12, 0x36, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66,
	0x2f, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x2f, 0x6d, 0x61,
	0x73, 0x74, 0x65, 0x72, 0x2f, 0x4c, 0x49, 0x43, 0x45, 0x4e, 0x53, 0x45, 0x32, 0x05, 0x31, 0x2e,
	0x35, 0x2e, 0x30, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x2e, 0x6b, 0x61, 0x73, 0x42, 0x08, 0x4b, 0x61,
	0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2f, 0x70, 0x6c, 0x61,
	0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2f, 0x67,
	0x6f, 0x2f, 0x6b, 0x61, 0x73, 0xa2, 0x02, 0x03, 0x4b, 0x58, 0x58, 0xaa, 0x02, 0x03, 0x4b, 0x61,
	0x73, 0xca, 0x02, 0x03, 0x4b, 0x61, 0x73, 0xe2, 0x02, 0x0f, 0x4b, 0x61, 0x73, 0x5c, 0x47, 0x50,
	0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x03, 0x4b, 0x61, 0x73, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_kas_kas_proto_rawDescOnce sync.Once
	file_kas_kas_proto_rawDescData = file_kas_kas_proto_rawDesc
)

func file_kas_kas_proto_rawDescGZIP() []byte {
	file_kas_kas_proto_rawDescOnce.Do(func() {
		file_kas_kas_proto_rawDescData = protoimpl.X.CompressGZIP(file_kas_kas_proto_rawDescData)
	})
	return file_kas_kas_proto_rawDescData
}

var file_kas_kas_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_kas_kas_proto_goTypes = []interface{}{
	(*InfoRequest)(nil),            // 0: kas.InfoRequest
	(*InfoResponse)(nil),           // 1: kas.InfoResponse
	(*LegacyPublicKeyRequest)(nil), // 2: kas.LegacyPublicKeyRequest
	(*PublicKeyRequest)(nil),       // 3: kas.PublicKeyRequest
	(*PublicKeyResponse)(nil),      // 4: kas.PublicKeyResponse
	(*RewrapRequest)(nil),          // 5: kas.RewrapRequest
	(*RewrapResponse)(nil),         // 6: kas.RewrapResponse
	nil,                            // 7: kas.RewrapResponse.MetadataEntry
	(*structpb.Value)(nil),         // 8: google.protobuf.Value
	(*wrapperspb.StringValue)(nil), // 9: google.protobuf.StringValue
}
var file_kas_kas_proto_depIdxs = []int32{
	7, // 0: kas.RewrapResponse.metadata:type_name -> kas.RewrapResponse.MetadataEntry
	8, // 1: kas.RewrapResponse.MetadataEntry.value:type_name -> google.protobuf.Value
	0, // 2: kas.AccessService.Info:input_type -> kas.InfoRequest
	3, // 3: kas.AccessService.PublicKey:input_type -> kas.PublicKeyRequest
	2, // 4: kas.AccessService.LegacyPublicKey:input_type -> kas.LegacyPublicKeyRequest
	5, // 5: kas.AccessService.Rewrap:input_type -> kas.RewrapRequest
	1, // 6: kas.AccessService.Info:output_type -> kas.InfoResponse
	4, // 7: kas.AccessService.PublicKey:output_type -> kas.PublicKeyResponse
	9, // 8: kas.AccessService.LegacyPublicKey:output_type -> google.protobuf.StringValue
	6, // 9: kas.AccessService.Rewrap:output_type -> kas.RewrapResponse
	6, // [6:10] is the sub-list for method output_type
	2, // [2:6] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_kas_kas_proto_init() }
func file_kas_kas_proto_init() {
	if File_kas_kas_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_kas_kas_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InfoRequest); i {
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
		file_kas_kas_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InfoResponse); i {
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
		file_kas_kas_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LegacyPublicKeyRequest); i {
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
		file_kas_kas_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicKeyRequest); i {
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
		file_kas_kas_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicKeyResponse); i {
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
		file_kas_kas_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RewrapRequest); i {
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
		file_kas_kas_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RewrapResponse); i {
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
			RawDescriptor: file_kas_kas_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_kas_kas_proto_goTypes,
		DependencyIndexes: file_kas_kas_proto_depIdxs,
		MessageInfos:      file_kas_kas_proto_msgTypes,
	}.Build()
	File_kas_kas_proto = out.File
	file_kas_kas_proto_rawDesc = nil
	file_kas_kas_proto_goTypes = nil
	file_kas_kas_proto_depIdxs = nil
}
