"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_sym_db = _symbol_database.Default()
from ...common.v1 import common_pb2 as common_dot_v1_dot_common__pb2
from ...google.api import annotations_pb2 as google_dot_api_dot_annotations__pb2
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1eattributes/v1/attributes.proto\x12\rattributes.v1\x1a\x16common/v1/common.proto\x1a\x1cgoogle/api/annotations.proto"\x93\x01\n\x0cAttributeSet\x12=\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorR\ndescriptor\x12D\n\x0bdefinitions\x18\x02 \x03(\x0b2".attributes.v1.AttributeDefinitionR\x0bdefinitions"\xd8\x03\n\x13AttributeDefinition\x12=\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorR\ndescriptor\x12\x12\n\x04name\x18\x02 \x01(\tR\x04name\x12H\n\x04rule\x18\x03 \x01(\x0e24.attributes.v1.AttributeDefinition.AttributeRuleTypeR\x04rule\x12?\n\x06values\x18\x04 \x03(\x0b2\'.attributes.v1.AttributeDefinitionValueR\x06values\x12B\n\x08group_by\x18\t \x03(\x0b2\'.attributes.v1.AttributeDefinitionValueR\x07groupBy"\x9e\x01\n\x11AttributeRuleType\x12#\n\x1fATTRIBUTE_RULE_TYPE_UNSPECIFIED\x10\x00\x12\x1e\n\x1aATTRIBUTE_RULE_TYPE_ALL_OF\x10\x01\x12\x1e\n\x1aATTRIBUTE_RULE_TYPE_ANY_OF\x10\x02\x12$\n ATTRIBUTE_RULE_TYPE_HIERARCHICAL\x10\x03"\xac\x01\n\x1cAttributeDefinitionReference\x12?\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorH\x00R\ndescriptor\x12D\n\ndefinition\x18\x02 \x01(\x0b2".attributes.v1.AttributeDefinitionH\x00R\ndefinitionB\x05\n\x03ref"\xa1\x01\n\x18AttributeDefinitionValue\x12=\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorR\ndescriptor\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value\x120\n\x14attribute_public_key\x18\x03 \x01(\tR\x12attributePublicKey"\xb5\x01\n\x17AttributeValueReference\x12?\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorH\x00R\ndescriptor\x12R\n\x0fattribute_value\x18\x02 \x01(\x0b2\'.attributes.v1.AttributeDefinitionValueH\x00R\x0eattributeValueB\x05\n\x03ref"\xe5\x01\n\x0eAttributeGroup\x12=\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorR\ndescriptor\x12G\n\x0bgroup_value\x18\x02 \x01(\x0b2&.attributes.v1.AttributeValueReferenceR\ngroupValue\x12K\n\rmember_values\x18\x03 \x03(\x0b2&.attributes.v1.AttributeValueReferenceR\x0cmemberValues"\x89\x01\n\x11AttributeGroupSet\x12=\n\ndescriptor\x18\x01 \x01(\x0b2\x1d.common.v1.ResourceDescriptorR\ndescriptor\x125\n\x06groups\x18\x02 \x03(\x0b2\x1d.attributes.v1.AttributeGroupR\x06groups"\x19\n\x17AttributeRequestOptions"x\n\x13GetAttributeRequest\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\x12E\n\x07options\x18\x02 \x01(\x0b2&.attributes.v1.AttributeRequestOptionsH\x00R\x07options\x88\x01\x01B\n\n\x08_options"Z\n\x14GetAttributeResponse\x12B\n\ndefinition\x18\x01 \x01(\x0b2".attributes.v1.AttributeDefinitionR\ndefinition"j\n\x15ListAttributesRequest\x12E\n\x07options\x18\x01 \x01(\x0b2&.attributes.v1.AttributeRequestOptionsH\x00R\x07options\x88\x01\x01B\n\n\x08_options"^\n\x16ListAttributesResponse\x12D\n\x0bdefinitions\x18\x01 \x03(\x0b2".attributes.v1.AttributeDefinitionR\x0bdefinitions"\\\n\x16CreateAttributeRequest\x12B\n\ndefinition\x18\x01 \x01(\x0b2".attributes.v1.AttributeDefinitionR\ndefinition"\x19\n\x17CreateAttributeResponse"l\n\x16UpdateAttributeRequest\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\x12B\n\ndefinition\x18\x02 \x01(\x0b2".attributes.v1.AttributeDefinitionR\ndefinition"\x19\n\x17UpdateAttributeResponse"(\n\x16DeleteAttributeRequest\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id"\x19\n\x17DeleteAttributeResponse"}\n\x18GetAttributeGroupRequest\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\x12E\n\x07options\x18\x02 \x01(\x0b2&.attributes.v1.AttributeRequestOptionsH\x00R\x07options\x88\x01\x01B\n\n\x08_options"P\n\x19GetAttributeGroupResponse\x123\n\x05group\x18\x01 \x01(\x0b2\x1d.attributes.v1.AttributeGroupR\x05group"o\n\x1aListAttributeGroupsRequest\x12E\n\x07options\x18\x01 \x01(\x0b2&.attributes.v1.AttributeRequestOptionsH\x00R\x07options\x88\x01\x01B\n\n\x08_options"T\n\x1bListAttributeGroupsResponse\x125\n\x06groups\x18\x01 \x03(\x0b2\x1d.attributes.v1.AttributeGroupR\x06groups"R\n\x1bCreateAttributeGroupRequest\x123\n\x05group\x18\x01 \x01(\x0b2\x1d.attributes.v1.AttributeGroupR\x05group"\x1e\n\x1cCreateAttributeGroupResponse"b\n\x1bUpdateAttributeGroupRequest\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id\x123\n\x05group\x18\x02 \x01(\x0b2\x1d.attributes.v1.AttributeGroupR\x05group"\x1e\n\x1cUpdateAttributeGroupResponse"-\n\x1bDeleteAttributeGroupRequest\x12\x0e\n\x02id\x18\x01 \x01(\tR\x02id"\x1e\n\x1cDeleteAttributeGroupResponse2\xea\n\n\x11AttributesService\x12t\n\x0cGetAttribute\x12".attributes.v1.GetAttributeRequest\x1a#.attributes.v1.GetAttributeResponse"\x1b\x82\xd3\xe4\x93\x02\x15\x12\x13/v1/attributes/{id}\x12\x8a\x01\n\x11GetAttributeGroup\x12\'.attributes.v1.GetAttributeGroupRequest\x1a(.attributes.v1.GetAttributeGroupResponse""\x82\xd3\xe4\x93\x02\x1c\x12\x1a/v1/attributes/groups/{id}\x12u\n\x0eListAttributes\x12$.attributes.v1.ListAttributesRequest\x1a%.attributes.v1.ListAttributesResponse"\x16\x82\xd3\xe4\x93\x02\x10\x12\x0e/v1/attributes\x12\x8b\x01\n\x13ListAttributeGroups\x12).attributes.v1.ListAttributeGroupsRequest\x1a*.attributes.v1.ListAttributeGroupsResponse"\x1d\x82\xd3\xe4\x93\x02\x17\x12\x15/v1/attributes/groups\x12{\n\x0fCreateAttribute\x12%.attributes.v1.CreateAttributeRequest\x1a&.attributes.v1.CreateAttributeResponse"\x19\x82\xd3\xe4\x93\x02\x13"\x0e/v1/attributes:\x01*\x12\x91\x01\n\x14CreateAttributeGroup\x12*.attributes.v1.CreateAttributeGroupRequest\x1a+.attributes.v1.CreateAttributeGroupResponse" \x82\xd3\xe4\x93\x02\x1a"\x15/v1/attributes/groups:\x01*\x12\x89\x01\n\x0fUpdateAttribute\x12%.attributes.v1.UpdateAttributeRequest\x1a&.attributes.v1.UpdateAttributeResponse"\'\x82\xd3\xe4\x93\x02!\x1a\x13/v1/attributes/{id}:\ndefinition\x12\x9a\x01\n\x14UpdateAttributeGroup\x12*.attributes.v1.UpdateAttributeGroupRequest\x1a+.attributes.v1.UpdateAttributeGroupResponse")\x82\xd3\xe4\x93\x02#\x1a\x1a/v1/attributes/groups/{id}:\x05group\x12}\n\x0fDeleteAttribute\x12%.attributes.v1.DeleteAttributeRequest\x1a&.attributes.v1.DeleteAttributeResponse"\x1b\x82\xd3\xe4\x93\x02\x15*\x13/v1/attributes/{id}\x12\x93\x01\n\x14DeleteAttributeGroup\x12*.attributes.v1.DeleteAttributeGroupRequest\x1a+.attributes.v1.DeleteAttributeGroupResponse""\x82\xd3\xe4\x93\x02\x1c*\x1a/v1/attributes/groups/{id}b\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'attributes.v1.attributes_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['GetAttribute']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['GetAttribute']._serialized_options = b'\x82\xd3\xe4\x93\x02\x15\x12\x13/v1/attributes/{id}'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['GetAttributeGroup']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['GetAttributeGroup']._serialized_options = b'\x82\xd3\xe4\x93\x02\x1c\x12\x1a/v1/attributes/groups/{id}'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['ListAttributes']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['ListAttributes']._serialized_options = b'\x82\xd3\xe4\x93\x02\x10\x12\x0e/v1/attributes'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['ListAttributeGroups']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['ListAttributeGroups']._serialized_options = b'\x82\xd3\xe4\x93\x02\x17\x12\x15/v1/attributes/groups'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['CreateAttribute']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['CreateAttribute']._serialized_options = b'\x82\xd3\xe4\x93\x02\x13"\x0e/v1/attributes:\x01*'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['CreateAttributeGroup']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['CreateAttributeGroup']._serialized_options = b'\x82\xd3\xe4\x93\x02\x1a"\x15/v1/attributes/groups:\x01*'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['UpdateAttribute']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['UpdateAttribute']._serialized_options = b'\x82\xd3\xe4\x93\x02!\x1a\x13/v1/attributes/{id}:\ndefinition'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['UpdateAttributeGroup']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['UpdateAttributeGroup']._serialized_options = b'\x82\xd3\xe4\x93\x02#\x1a\x1a/v1/attributes/groups/{id}:\x05group'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['DeleteAttribute']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['DeleteAttribute']._serialized_options = b'\x82\xd3\xe4\x93\x02\x15*\x13/v1/attributes/{id}'
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['DeleteAttributeGroup']._options = None
    _globals['_ATTRIBUTESSERVICE'].methods_by_name['DeleteAttributeGroup']._serialized_options = b'\x82\xd3\xe4\x93\x02\x1c*\x1a/v1/attributes/groups/{id}'
    _globals['_ATTRIBUTESET']._serialized_start = 104
    _globals['_ATTRIBUTESET']._serialized_end = 251
    _globals['_ATTRIBUTEDEFINITION']._serialized_start = 254
    _globals['_ATTRIBUTEDEFINITION']._serialized_end = 726
    _globals['_ATTRIBUTEDEFINITION_ATTRIBUTERULETYPE']._serialized_start = 568
    _globals['_ATTRIBUTEDEFINITION_ATTRIBUTERULETYPE']._serialized_end = 726
    _globals['_ATTRIBUTEDEFINITIONREFERENCE']._serialized_start = 729
    _globals['_ATTRIBUTEDEFINITIONREFERENCE']._serialized_end = 901
    _globals['_ATTRIBUTEDEFINITIONVALUE']._serialized_start = 904
    _globals['_ATTRIBUTEDEFINITIONVALUE']._serialized_end = 1065
    _globals['_ATTRIBUTEVALUEREFERENCE']._serialized_start = 1068
    _globals['_ATTRIBUTEVALUEREFERENCE']._serialized_end = 1249
    _globals['_ATTRIBUTEGROUP']._serialized_start = 1252
    _globals['_ATTRIBUTEGROUP']._serialized_end = 1481
    _globals['_ATTRIBUTEGROUPSET']._serialized_start = 1484
    _globals['_ATTRIBUTEGROUPSET']._serialized_end = 1621
    _globals['_ATTRIBUTEREQUESTOPTIONS']._serialized_start = 1623
    _globals['_ATTRIBUTEREQUESTOPTIONS']._serialized_end = 1648
    _globals['_GETATTRIBUTEREQUEST']._serialized_start = 1650
    _globals['_GETATTRIBUTEREQUEST']._serialized_end = 1770
    _globals['_GETATTRIBUTERESPONSE']._serialized_start = 1772
    _globals['_GETATTRIBUTERESPONSE']._serialized_end = 1862
    _globals['_LISTATTRIBUTESREQUEST']._serialized_start = 1864
    _globals['_LISTATTRIBUTESREQUEST']._serialized_end = 1970
    _globals['_LISTATTRIBUTESRESPONSE']._serialized_start = 1972
    _globals['_LISTATTRIBUTESRESPONSE']._serialized_end = 2066
    _globals['_CREATEATTRIBUTEREQUEST']._serialized_start = 2068
    _globals['_CREATEATTRIBUTEREQUEST']._serialized_end = 2160
    _globals['_CREATEATTRIBUTERESPONSE']._serialized_start = 2162
    _globals['_CREATEATTRIBUTERESPONSE']._serialized_end = 2187
    _globals['_UPDATEATTRIBUTEREQUEST']._serialized_start = 2189
    _globals['_UPDATEATTRIBUTEREQUEST']._serialized_end = 2297
    _globals['_UPDATEATTRIBUTERESPONSE']._serialized_start = 2299
    _globals['_UPDATEATTRIBUTERESPONSE']._serialized_end = 2324
    _globals['_DELETEATTRIBUTEREQUEST']._serialized_start = 2326
    _globals['_DELETEATTRIBUTEREQUEST']._serialized_end = 2366
    _globals['_DELETEATTRIBUTERESPONSE']._serialized_start = 2368
    _globals['_DELETEATTRIBUTERESPONSE']._serialized_end = 2393
    _globals['_GETATTRIBUTEGROUPREQUEST']._serialized_start = 2395
    _globals['_GETATTRIBUTEGROUPREQUEST']._serialized_end = 2520
    _globals['_GETATTRIBUTEGROUPRESPONSE']._serialized_start = 2522
    _globals['_GETATTRIBUTEGROUPRESPONSE']._serialized_end = 2602
    _globals['_LISTATTRIBUTEGROUPSREQUEST']._serialized_start = 2604
    _globals['_LISTATTRIBUTEGROUPSREQUEST']._serialized_end = 2715
    _globals['_LISTATTRIBUTEGROUPSRESPONSE']._serialized_start = 2717
    _globals['_LISTATTRIBUTEGROUPSRESPONSE']._serialized_end = 2801
    _globals['_CREATEATTRIBUTEGROUPREQUEST']._serialized_start = 2803
    _globals['_CREATEATTRIBUTEGROUPREQUEST']._serialized_end = 2885
    _globals['_CREATEATTRIBUTEGROUPRESPONSE']._serialized_start = 2887
    _globals['_CREATEATTRIBUTEGROUPRESPONSE']._serialized_end = 2917
    _globals['_UPDATEATTRIBUTEGROUPREQUEST']._serialized_start = 2919
    _globals['_UPDATEATTRIBUTEGROUPREQUEST']._serialized_end = 3017
    _globals['_UPDATEATTRIBUTEGROUPRESPONSE']._serialized_start = 3019
    _globals['_UPDATEATTRIBUTEGROUPRESPONSE']._serialized_end = 3049
    _globals['_DELETEATTRIBUTEGROUPREQUEST']._serialized_start = 3051
    _globals['_DELETEATTRIBUTEGROUPREQUEST']._serialized_end = 3096
    _globals['_DELETEATTRIBUTEGROUPRESPONSE']._serialized_start = 3098
    _globals['_DELETEATTRIBUTEGROUPRESPONSE']._serialized_end = 3128
    _globals['_ATTRIBUTESSERVICE']._serialized_start = 3131
    _globals['_ATTRIBUTESSERVICE']._serialized_end = 4517