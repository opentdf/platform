"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16common/v1/common.proto\x12\tcommon.v1"\x98\x03\n\x12ResourceDescriptor\x121\n\x04type\x18\x01 \x01(\x0e2\x1d.common.v1.PolicyResourceTypeR\x04type\x12\x0e\n\x02id\x18\x02 \x01(\x05R\x02id\x12\x18\n\x07version\x18\x03 \x01(\x05R\x07version\x12\x12\n\x04name\x18\x04 \x01(\tR\x04name\x12\x1c\n\tnamespace\x18\x05 \x01(\tR\tnamespace\x12\x10\n\x03fqn\x18\x06 \x01(\tR\x03fqn\x12A\n\x06labels\x18\x07 \x03(\x0b2).common.v1.ResourceDescriptor.LabelsEntryR\x06labels\x12 \n\x0bdescription\x18\x08 \x01(\tR\x0bdescription\x12A\n\x0cdependencies\x18\t \x03(\x0b2\x1d.common.v1.ResourceDependencyR\x0cdependencies\x1a9\n\x0bLabelsEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x028\x01"\x7f\n\x12ResourceDependency\x12\x1c\n\tnamespace\x18\x01 \x01(\tR\tnamespace\x12\x18\n\x07version\x18\x02 \x01(\tR\x07version\x121\n\x04type\x18\x03 \x01(\x0e2\x1d.common.v1.PolicyResourceTypeR\x04type"\xdc\x02\n\x10ResourceSelector\x12\x1c\n\tnamespace\x18\x01 \x01(\tR\tnamespace\x12\x18\n\x07version\x18\x02 \x01(\tR\x07version\x12\x14\n\x04name\x18\x03 \x01(\tH\x00R\x04name\x12R\n\x0elabel_selector\x18\x04 \x01(\x0b2).common.v1.ResourceSelector.LabelSelectorH\x00R\rlabelSelector\x1a\x99\x01\n\rLabelSelector\x12M\n\x06labels\x18\x01 \x03(\x0b25.common.v1.ResourceSelector.LabelSelector.LabelsEntryR\x06labels\x1a9\n\x0bLabelsEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x028\x01B\n\n\x08selector*\xb1\x03\n\x12PolicyResourceType\x12$\n POLICY_RESOURCE_TYPE_UNSPECIFIED\x10\x00\x12*\n&POLICY_RESOURCE_TYPE_RESOURCE_ENCODING\x10\x01\x122\n.POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM\x10\x02\x122\n.POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING\x10\x03\x120\n,POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP\x10\x04\x121\n-POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING\x10\x05\x12#\n\x1fPOLICY_RESOURCE_TYPE_KEY_ACCESS\x10\x06\x12-\n)POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION\x10\x07\x12(\n$POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP\x10\x08b\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'common.v1.common_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals['_RESOURCEDESCRIPTOR_LABELSENTRY']._options = None
    _globals['_RESOURCEDESCRIPTOR_LABELSENTRY']._serialized_options = b'8\x01'
    _globals['_RESOURCESELECTOR_LABELSELECTOR_LABELSENTRY']._options = None
    _globals['_RESOURCESELECTOR_LABELSELECTOR_LABELSENTRY']._serialized_options = b'8\x01'
    _globals['_POLICYRESOURCETYPE']._serialized_start = 929
    _globals['_POLICYRESOURCETYPE']._serialized_end = 1362
    _globals['_RESOURCEDESCRIPTOR']._serialized_start = 38
    _globals['_RESOURCEDESCRIPTOR']._serialized_end = 446
    _globals['_RESOURCEDESCRIPTOR_LABELSENTRY']._serialized_start = 389
    _globals['_RESOURCEDESCRIPTOR_LABELSENTRY']._serialized_end = 446
    _globals['_RESOURCEDEPENDENCY']._serialized_start = 448
    _globals['_RESOURCEDEPENDENCY']._serialized_end = 575
    _globals['_RESOURCESELECTOR']._serialized_start = 578
    _globals['_RESOURCESELECTOR']._serialized_end = 926
    _globals['_RESOURCESELECTOR_LABELSELECTOR']._serialized_start = 761
    _globals['_RESOURCESELECTOR_LABELSELECTOR']._serialized_end = 914
    _globals['_RESOURCESELECTOR_LABELSELECTOR_LABELSENTRY']._serialized_start = 389
    _globals['_RESOURCESELECTOR_LABELSELECTOR_LABELSENTRY']._serialized_end = 446