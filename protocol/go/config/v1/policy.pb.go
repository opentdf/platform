// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: config/v1/policy.proto

package configv1

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	config "github.com/opentdf/platform/protocol/go/config"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/descriptorpb"
	_ "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PolicyConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HttpCacheSecs *config.IntField `protobuf:"bytes,1,opt,name=http_cache_secs,json=httpCacheSecs,proto3" json:"http_cache_secs,omitempty"`
}

func (x *PolicyConfig) Reset() {
	*x = PolicyConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_v1_policy_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PolicyConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PolicyConfig) ProtoMessage() {}

func (x *PolicyConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_v1_policy_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PolicyConfig.ProtoReflect.Descriptor instead.
func (*PolicyConfig) Descriptor() ([]byte, []int) {
	return file_config_v1_policy_proto_rawDescGZIP(), []int{0}
}

func (x *PolicyConfig) GetHttpCacheSecs() *config.IntField {
	if x != nil {
		return x.HttpCacheSecs
	}
	return nil
}

var File_config_v1_policy_proto protoreflect.FileDescriptor

var file_config_v1_policy_proto_rawDesc = []byte{
	0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x62, 0x75, 0x66, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xb7, 0x01, 0x0a, 0x0c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x12, 0xa6, 0x01, 0x0a, 0x0f, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x63, 0x61, 0x63, 0x68, 0x65,
	0x5f, 0x73, 0x65, 0x63, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x49, 0x6e, 0x74, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x42, 0x6c, 0xba,
	0x48, 0x03, 0xc8, 0x01, 0x01, 0x82, 0xb5, 0x18, 0x62, 0x0a, 0x29, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x52, 0x50, 0x43, 0x20, 0x48, 0x54, 0x54, 0x50, 0x20, 0x43, 0x61, 0x63, 0x68, 0x65,
	0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x63,
	0x6f, 0x6e, 0x64, 0x73, 0x12, 0x30, 0x53, 0x65, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x43, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x52, 0x50, 0x43, 0x20, 0x48, 0x54, 0x54, 0x50, 0x20, 0x43, 0x61,
	0x63, 0x68, 0x65, 0x20, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x28, 0x73, 0x65,
	0x63, 0x6f, 0x6e, 0x64, 0x73, 0x29, 0x1a, 0x03, 0x33, 0x30, 0x30, 0x52, 0x0d, 0x68, 0x74, 0x74,
	0x70, 0x43, 0x61, 0x63, 0x68, 0x65, 0x53, 0x65, 0x63, 0x73, 0x42, 0x9d, 0x01, 0x0a, 0x0d, 0x63,
	0x6f, 0x6d, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x42, 0x0b, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3a, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x74, 0x64, 0x66, 0x2f,
	0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
	0x6c, 0x2f, 0x67, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x76, 0x31, 0x3b, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x43, 0x58, 0x58, 0xaa, 0x02, 0x09,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x09, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x15, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5c, 0x56,
	0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0a,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_config_v1_policy_proto_rawDescOnce sync.Once
	file_config_v1_policy_proto_rawDescData = file_config_v1_policy_proto_rawDesc
)

func file_config_v1_policy_proto_rawDescGZIP() []byte {
	file_config_v1_policy_proto_rawDescOnce.Do(func() {
		file_config_v1_policy_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_v1_policy_proto_rawDescData)
	})
	return file_config_v1_policy_proto_rawDescData
}

var file_config_v1_policy_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_config_v1_policy_proto_goTypes = []interface{}{
	(*PolicyConfig)(nil),    // 0: config.v1.PolicyConfig
	(*config.IntField)(nil), // 1: config.IntField
}
var file_config_v1_policy_proto_depIdxs = []int32{
	1, // 0: config.v1.PolicyConfig.http_cache_secs:type_name -> config.IntField
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_config_v1_policy_proto_init() }
func file_config_v1_policy_proto_init() {
	if File_config_v1_policy_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_v1_policy_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PolicyConfig); i {
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
			RawDescriptor: file_config_v1_policy_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_v1_policy_proto_goTypes,
		DependencyIndexes: file_config_v1_policy_proto_depIdxs,
		MessageInfos:      file_config_v1_policy_proto_msgTypes,
	}.Build()
	File_config_v1_policy_proto = out.File
	file_config_v1_policy_proto_rawDesc = nil
	file_config_v1_policy_proto_goTypes = nil
	file_config_v1_policy_proto_depIdxs = nil
}
