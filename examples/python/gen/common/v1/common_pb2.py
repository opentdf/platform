"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16common/v1/common.proto\x12\tcommon.v1"\xe9\x01\n\x12ResourceDescriptor\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\x12\x18\n\x07version\x18\x02 \x01(\tR\x07version\x12\x1c\n\tnamespace\x18\x03 \x01(\tR\tnamespace\x12\x10\n\x03fqn\x18\x04 \x01(\tR\x03fqn\x12\x14\n\x05label\x18\x05 \x01(\tR\x05label\x12 \n\x0bdescription\x18\x06 \x01(\tR\x0bdescription\x12A\n\x0cdependencies\x18\x07 \x03(\x0b2\x1d.common.v1.ResourceDependencyR\x0cdependencies"\xf0\x02\n\x12ResourceDependency\x12\x1c\n\tnamespace\x18\x01 \x01(\tR\tnamespace\x12\x18\n\x07version\x18\x02 \x01(\tR\x07version\x12D\n\x04type\x18\x03 \x01(\x0e20.common.v1.ResourceDependency.PolicyResourceTypeR\x04type"\xdb\x01\n\x12PolicyResourceType\x12$\n POLICY_RESOURCE_TYPE_UNSPECIFIED\x10\x00\x12*\n&POLICY_RESOURCE_TYPE_RESOURCE_ENCODING\x10\x01\x12)\n%POLICY_RESOURCE_TYPE_SUBJECT_ENCODING\x10\x02\x12#\n\x1fPOLICY_RESOURCE_TYPE_KEY_ACCESS\x10\x03\x12#\n\x1fPOLICY_RESOURCE_TYPE_ATTRIBUTES\x10\x04b\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'common.v1.common_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals['_RESOURCEDESCRIPTOR']._serialized_start = 38
    _globals['_RESOURCEDESCRIPTOR']._serialized_end = 271
    _globals['_RESOURCEDEPENDENCY']._serialized_start = 274
    _globals['_RESOURCEDEPENDENCY']._serialized_end = 642
    _globals['_RESOURCEDEPENDENCY_POLICYRESOURCETYPE']._serialized_start = 423
    _globals['_RESOURCEDEPENDENCY_POLICYRESOURCETYPE']._serialized_end = 642