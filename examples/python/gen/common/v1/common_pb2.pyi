from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union
DESCRIPTOR: _descriptor.FileDescriptor

class ResourceDescriptor(_message.Message):
    __slots__ = ('id', 'version', 'namespace', 'fqn', 'label', 'description', 'dependencies')
    ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    FQN_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEPENDENCIES_FIELD_NUMBER: _ClassVar[int]
    id: str
    version: str
    namespace: str
    fqn: str
    label: str
    description: str
    dependencies: _containers.RepeatedCompositeFieldContainer[ResourceDependency]

    def __init__(self, id: _Optional[str]=..., version: _Optional[str]=..., namespace: _Optional[str]=..., fqn: _Optional[str]=..., label: _Optional[str]=..., description: _Optional[str]=..., dependencies: _Optional[_Iterable[_Union[ResourceDependency, _Mapping]]]=...) -> None:
        ...

class ResourceDependency(_message.Message):
    __slots__ = ('namespace', 'version', 'type')

    class PolicyResourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        POLICY_RESOURCE_TYPE_UNSPECIFIED: _ClassVar[ResourceDependency.PolicyResourceType]
        POLICY_RESOURCE_TYPE_RESOURCE_ENCODING: _ClassVar[ResourceDependency.PolicyResourceType]
        POLICY_RESOURCE_TYPE_SUBJECT_ENCODING: _ClassVar[ResourceDependency.PolicyResourceType]
        POLICY_RESOURCE_TYPE_KEY_ACCESS: _ClassVar[ResourceDependency.PolicyResourceType]
        POLICY_RESOURCE_TYPE_ATTRIBUTES: _ClassVar[ResourceDependency.PolicyResourceType]
    POLICY_RESOURCE_TYPE_UNSPECIFIED: ResourceDependency.PolicyResourceType
    POLICY_RESOURCE_TYPE_RESOURCE_ENCODING: ResourceDependency.PolicyResourceType
    POLICY_RESOURCE_TYPE_SUBJECT_ENCODING: ResourceDependency.PolicyResourceType
    POLICY_RESOURCE_TYPE_KEY_ACCESS: ResourceDependency.PolicyResourceType
    POLICY_RESOURCE_TYPE_ATTRIBUTES: ResourceDependency.PolicyResourceType
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    version: str
    type: ResourceDependency.PolicyResourceType

    def __init__(self, namespace: _Optional[str]=..., version: _Optional[str]=..., type: _Optional[_Union[ResourceDependency.PolicyResourceType, str]]=...) -> None:
        ...