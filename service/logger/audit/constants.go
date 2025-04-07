package audit

import (
	"encoding/json"
)

type ObjectType int

const (
	ObjectTypeSubjectMapping ObjectType = iota
	ObjectTypeResourceMapping
	ObjectTypeAttributeDefinition
	ObjectTypeAttributeValue
	ObjectTypeNamespace
	ObjectTypeConditionSet
	ObjectTypeKasRegistry
	ObjectTypeKasAttributeNamespaceAssignment
	ObjectTypeKasAttributeDefinitionAssignment
	ObjectTypeKasAttributeValueAssignment
	ObjectTypeKeyObject
	ObjectTypeEntityObject
	ObjectTypeResourceMappingGroup
	ObjectTypePublicKey
	ObjectTypeAction
	ObjectTypeRegisteredResource
	ObjectTypeRegisteredResourceValue
	ObjectTypeKeyManagementProviderConfig
	ObjectTypeKasRegistryKeys
)

func (ot ObjectType) String() string {
	return [...]string{
		"subject_mapping",
		"resource_mapping",
		"attribute_definition",
		"attribute_value",
		"namespace",
		"condition_set",
		"kas_registry",
		"kas_attribute_namespace_assignment",
		"kas_attribute_definition_assignment",
		"kas_attribute_value_assignment",
		"key_object",
		"entity_object",
		"resource_mapping_group",
		"public_key",
		"action",
		"registered_resource",
		"registered_resource_value",
		"key_management_provider_config",
		"kas_registry_keys",
	}[ot]
}

func (ot ObjectType) MarshalJSON() ([]byte, error) {
	return json.Marshal(ot.String())
}

type ActionType int

const (
	ActionTypeCreate ActionType = iota
	ActionTypeRead
	ActionTypeUpdate
	ActionTypeDelete
	ActionTypeRewrap
)

func (at ActionType) String() string {
	return [...]string{
		"create",
		"read",
		"update",
		"delete",
		"rewrap",
	}[at]
}

func (at ActionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(at.String())
}

type ActionResult int

const (
	ActionResultSuccess ActionResult = iota
	ActionResultFailure
	ActionResultError
	ActionResultEncrypt
	ActionResultBlock
	ActionResultIgnore
	ActionResultOverride
	ActionResultCancel
)

func (ar ActionResult) String() string {
	return [...]string{
		"success",
		"failure",
		"error",
		"encrypt",
		"block",
		"ignore",
		"override",
		"cancel",
	}[ar]
}

func (ar ActionResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(ar.String())
}
