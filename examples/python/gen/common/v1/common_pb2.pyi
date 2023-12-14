from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union
DESCRIPTOR: _descriptor.FileDescriptor

class PolicyResourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_RESOURCE_TYPE_UNSPECIFIED: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_RESOURCE_ENCODING: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_KEY_ACCESS: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION: _ClassVar[PolicyResourceType]
    POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP: _ClassVar[PolicyResourceType]
POLICY_RESOURCE_TYPE_UNSPECIFIED: PolicyResourceType
POLICY_RESOURCE_TYPE_RESOURCE_ENCODING: PolicyResourceType
POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM: PolicyResourceType
POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING: PolicyResourceType
POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP: PolicyResourceType
POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING: PolicyResourceType
POLICY_RESOURCE_TYPE_KEY_ACCESS: PolicyResourceType
POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION: PolicyResourceType
POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP: PolicyResourceType

class ResourceDescriptor(_message.Message):
    __slots__ = ('type', 'id', 'version', 'name', 'namespace', 'fqn', 'labels', 'description', 'dependencies')

    class LabelsEntry(_message.Message):
        __slots__ = ('key', 'value')
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str

        def __init__(self, key: _Optional[str]=..., value: _Optional[str]=...) -> None:
            ...
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    FQN_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEPENDENCIES_FIELD_NUMBER: _ClassVar[int]
    type: PolicyResourceType
    id: int
    version: int
    name: str
    namespace: str
    fqn: str
    labels: _containers.ScalarMap[str, str]
    description: str
    dependencies: _containers.RepeatedCompositeFieldContainer[ResourceDependency]

    def __init__(self, type: _Optional[_Union[PolicyResourceType, str]]=..., id: _Optional[int]=..., version: _Optional[int]=..., name: _Optional[str]=..., namespace: _Optional[str]=..., fqn: _Optional[str]=..., labels: _Optional[_Mapping[str, str]]=..., description: _Optional[str]=..., dependencies: _Optional[_Iterable[_Union[ResourceDependency, _Mapping]]]=...) -> None:
        ...

class ResourceDependency(_message.Message):
    __slots__ = ('namespace', 'version', 'type')
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    version: str
    type: PolicyResourceType

    def __init__(self, namespace: _Optional[str]=..., version: _Optional[str]=..., type: _Optional[_Union[PolicyResourceType, str]]=...) -> None:
        ...

class ResourceSelector(_message.Message):
    __slots__ = ('namespace', 'version', 'name', 'label_selector')

    class LabelSelector(_message.Message):
        __slots__ = ('labels',)

        class LabelsEntry(_message.Message):
            __slots__ = ('key', 'value')
            KEY_FIELD_NUMBER: _ClassVar[int]
            VALUE_FIELD_NUMBER: _ClassVar[int]
            key: str
            value: str

            def __init__(self, key: _Optional[str]=..., value: _Optional[str]=...) -> None:
                ...
        LABELS_FIELD_NUMBER: _ClassVar[int]
        labels: _containers.ScalarMap[str, str]

        def __init__(self, labels: _Optional[_Mapping[str, str]]=...) -> None:
            ...
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABEL_SELECTOR_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    version: str
    name: str
    label_selector: ResourceSelector.LabelSelector

    def __init__(self, namespace: _Optional[str]=..., version: _Optional[str]=..., name: _Optional[str]=..., label_selector: _Optional[_Union[ResourceSelector.LabelSelector, _Mapping]]=...) -> None:
        ...