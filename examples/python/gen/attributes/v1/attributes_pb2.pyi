from common.v1 import common_pb2 as _common_pb2
from google.api import annotations_pb2 as _annotations_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union
DESCRIPTOR: _descriptor.FileDescriptor

class AttributeSet(_message.Message):
    __slots__ = ('descriptor', 'definitions')
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    DEFINITIONS_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    definitions: _containers.RepeatedCompositeFieldContainer[AttributeDefinition]

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., definitions: _Optional[_Iterable[_Union[AttributeDefinition, _Mapping]]]=...) -> None:
        ...

class AttributeDefinition(_message.Message):
    __slots__ = ('descriptor', 'name', 'rule', 'values', 'group_by')

    class AttributeRuleType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ATTRIBUTE_RULE_TYPE_UNSPECIFIED: _ClassVar[AttributeDefinition.AttributeRuleType]
        ATTRIBUTE_RULE_TYPE_ALL_OF: _ClassVar[AttributeDefinition.AttributeRuleType]
        ATTRIBUTE_RULE_TYPE_ANY_OF: _ClassVar[AttributeDefinition.AttributeRuleType]
        ATTRIBUTE_RULE_TYPE_HIERARCHICAL: _ClassVar[AttributeDefinition.AttributeRuleType]
    ATTRIBUTE_RULE_TYPE_UNSPECIFIED: AttributeDefinition.AttributeRuleType
    ATTRIBUTE_RULE_TYPE_ALL_OF: AttributeDefinition.AttributeRuleType
    ATTRIBUTE_RULE_TYPE_ANY_OF: AttributeDefinition.AttributeRuleType
    ATTRIBUTE_RULE_TYPE_HIERARCHICAL: AttributeDefinition.AttributeRuleType
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    GROUP_BY_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    name: str
    rule: AttributeDefinition.AttributeRuleType
    values: _containers.RepeatedCompositeFieldContainer[AttributeDefinitionValue]
    group_by: _containers.RepeatedCompositeFieldContainer[AttributeDefinitionValue]

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., name: _Optional[str]=..., rule: _Optional[_Union[AttributeDefinition.AttributeRuleType, str]]=..., values: _Optional[_Iterable[_Union[AttributeDefinitionValue, _Mapping]]]=..., group_by: _Optional[_Iterable[_Union[AttributeDefinitionValue, _Mapping]]]=...) -> None:
        ...

class AttributeDefinitionReference(_message.Message):
    __slots__ = ('descriptor', 'definition')
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    DEFINITION_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    definition: AttributeDefinition

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., definition: _Optional[_Union[AttributeDefinition, _Mapping]]=...) -> None:
        ...

class AttributeDefinitionValue(_message.Message):
    __slots__ = ('descriptor', 'value', 'attribute_public_key')
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTE_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    value: str
    attribute_public_key: str

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., value: _Optional[str]=..., attribute_public_key: _Optional[str]=...) -> None:
        ...

class AttributeValueReference(_message.Message):
    __slots__ = ('descriptor', 'attribute_value')
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTE_VALUE_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    attribute_value: AttributeDefinitionValue

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., attribute_value: _Optional[_Union[AttributeDefinitionValue, _Mapping]]=...) -> None:
        ...

class AttributeGroup(_message.Message):
    __slots__ = ('descriptor', 'group_value', 'member_values')
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    GROUP_VALUE_FIELD_NUMBER: _ClassVar[int]
    MEMBER_VALUES_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    group_value: AttributeValueReference
    member_values: _containers.RepeatedCompositeFieldContainer[AttributeValueReference]

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., group_value: _Optional[_Union[AttributeValueReference, _Mapping]]=..., member_values: _Optional[_Iterable[_Union[AttributeValueReference, _Mapping]]]=...) -> None:
        ...

class AttributeGroupSet(_message.Message):
    __slots__ = ('descriptor', 'groups')
    DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    descriptor: _common_pb2.ResourceDescriptor
    groups: _containers.RepeatedCompositeFieldContainer[AttributeGroup]

    def __init__(self, descriptor: _Optional[_Union[_common_pb2.ResourceDescriptor, _Mapping]]=..., groups: _Optional[_Iterable[_Union[AttributeGroup, _Mapping]]]=...) -> None:
        ...

class AttributeRequestOptions(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...

class GetAttributeRequest(_message.Message):
    __slots__ = ('id', 'options')
    ID_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    id: str
    options: AttributeRequestOptions

    def __init__(self, id: _Optional[str]=..., options: _Optional[_Union[AttributeRequestOptions, _Mapping]]=...) -> None:
        ...

class GetAttributeResponse(_message.Message):
    __slots__ = ('definition',)
    DEFINITION_FIELD_NUMBER: _ClassVar[int]
    definition: AttributeDefinition

    def __init__(self, definition: _Optional[_Union[AttributeDefinition, _Mapping]]=...) -> None:
        ...

class ListAttributesRequest(_message.Message):
    __slots__ = ('selector',)
    SELECTOR_FIELD_NUMBER: _ClassVar[int]
    selector: _common_pb2.ResourceSelector

    def __init__(self, selector: _Optional[_Union[_common_pb2.ResourceSelector, _Mapping]]=...) -> None:
        ...

class ListAttributesResponse(_message.Message):
    __slots__ = ('definitions',)
    DEFINITIONS_FIELD_NUMBER: _ClassVar[int]
    definitions: _containers.RepeatedCompositeFieldContainer[AttributeDefinition]

    def __init__(self, definitions: _Optional[_Iterable[_Union[AttributeDefinition, _Mapping]]]=...) -> None:
        ...

class CreateAttributeRequest(_message.Message):
    __slots__ = ('definition',)
    DEFINITION_FIELD_NUMBER: _ClassVar[int]
    definition: AttributeDefinition

    def __init__(self, definition: _Optional[_Union[AttributeDefinition, _Mapping]]=...) -> None:
        ...

class CreateAttributeResponse(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...

class UpdateAttributeRequest(_message.Message):
    __slots__ = ('id', 'definition')
    ID_FIELD_NUMBER: _ClassVar[int]
    DEFINITION_FIELD_NUMBER: _ClassVar[int]
    id: str
    definition: AttributeDefinition

    def __init__(self, id: _Optional[str]=..., definition: _Optional[_Union[AttributeDefinition, _Mapping]]=...) -> None:
        ...

class UpdateAttributeResponse(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...

class DeleteAttributeRequest(_message.Message):
    __slots__ = ('id',)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str

    def __init__(self, id: _Optional[str]=...) -> None:
        ...

class DeleteAttributeResponse(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...

class GetAttributeGroupRequest(_message.Message):
    __slots__ = ('id', 'options')
    ID_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    id: str
    options: AttributeRequestOptions

    def __init__(self, id: _Optional[str]=..., options: _Optional[_Union[AttributeRequestOptions, _Mapping]]=...) -> None:
        ...

class GetAttributeGroupResponse(_message.Message):
    __slots__ = ('group',)
    GROUP_FIELD_NUMBER: _ClassVar[int]
    group: AttributeGroup

    def __init__(self, group: _Optional[_Union[AttributeGroup, _Mapping]]=...) -> None:
        ...

class ListAttributeGroupsRequest(_message.Message):
    __slots__ = ('selector',)
    SELECTOR_FIELD_NUMBER: _ClassVar[int]
    selector: _common_pb2.ResourceSelector

    def __init__(self, selector: _Optional[_Union[_common_pb2.ResourceSelector, _Mapping]]=...) -> None:
        ...

class ListAttributeGroupsResponse(_message.Message):
    __slots__ = ('groups',)
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    groups: _containers.RepeatedCompositeFieldContainer[AttributeGroup]

    def __init__(self, groups: _Optional[_Iterable[_Union[AttributeGroup, _Mapping]]]=...) -> None:
        ...

class CreateAttributeGroupRequest(_message.Message):
    __slots__ = ('group',)
    GROUP_FIELD_NUMBER: _ClassVar[int]
    group: AttributeGroup

    def __init__(self, group: _Optional[_Union[AttributeGroup, _Mapping]]=...) -> None:
        ...

class CreateAttributeGroupResponse(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...

class UpdateAttributeGroupRequest(_message.Message):
    __slots__ = ('id', 'group')
    ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    id: str
    group: AttributeGroup

    def __init__(self, id: _Optional[str]=..., group: _Optional[_Union[AttributeGroup, _Mapping]]=...) -> None:
        ...

class UpdateAttributeGroupResponse(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...

class DeleteAttributeGroupRequest(_message.Message):
    __slots__ = ('id',)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str

    def __init__(self, id: _Optional[str]=...) -> None:
        ...

class DeleteAttributeGroupResponse(_message.Message):
    __slots__ = ()

    def __init__(self) -> None:
        ...