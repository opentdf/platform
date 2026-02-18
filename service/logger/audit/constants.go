package audit

import (
	"encoding/json"
	"fmt"
	"sync"
)

type ObjectType int

const (
	ObjectTypeSubjectMapping ObjectType = iota
	ObjectTypeResourceMapping
	ObjectTypeAttributeDefinition
	ObjectTypeAttributeValue
	ObjectTypeObligationDefinition
	ObjectTypeObligationValue
	ObjectTypeObligationTrigger
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
	ObjectTypeKasAttributeDefinitionKeyAssignment
	ObjectTypeKasAttributeValueKeyAssignment
	ObjectTypeKasAttributeNamespaceKeyAssignment
)

var auditTypeMu sync.RWMutex

var objectTypeNames = map[ObjectType]string{
	ObjectTypeSubjectMapping:                      "subject_mapping",
	ObjectTypeResourceMapping:                     "resource_mapping",
	ObjectTypeAttributeDefinition:                 "attribute_definition",
	ObjectTypeAttributeValue:                      "attribute_value",
	ObjectTypeObligationDefinition:                "obligation_definition",
	ObjectTypeObligationValue:                     "obligation_value",
	ObjectTypeObligationTrigger:                   "obligation_trigger",
	ObjectTypeNamespace:                           "namespace",
	ObjectTypeConditionSet:                        "condition_set",
	ObjectTypeKasRegistry:                         "kas_registry",
	ObjectTypeKasAttributeNamespaceAssignment:     "kas_attribute_namespace_assignment",
	ObjectTypeKasAttributeDefinitionAssignment:    "kas_attribute_definition_assignment",
	ObjectTypeKasAttributeValueAssignment:         "kas_attribute_value_assignment",
	ObjectTypeKeyObject:                           "key_object",
	ObjectTypeEntityObject:                        "entity_object",
	ObjectTypeResourceMappingGroup:                "resource_mapping_group",
	ObjectTypePublicKey:                           "public_key",
	ObjectTypeAction:                              "action",
	ObjectTypeRegisteredResource:                  "registered_resource",
	ObjectTypeRegisteredResourceValue:             "registered_resource_value",
	ObjectTypeKeyManagementProviderConfig:         "key_management_provider_config",
	ObjectTypeKasRegistryKeys:                     "kas_registry_keys",
	ObjectTypeKasAttributeDefinitionKeyAssignment: "kas_attribute_definition_key_assignment",
	ObjectTypeKasAttributeValueKeyAssignment:      "kas_attribute_value_key_assignment",
	ObjectTypeKasAttributeNamespaceKeyAssignment:  "kas_attribute_namespace_key_assignment",
}

func (ot ObjectType) String() string {
	auditTypeMu.RLock()
	name, ok := objectTypeNames[ot]
	auditTypeMu.RUnlock()
	if ok {
		return name
	}
	return fmt.Sprintf("object_type_%d", ot)
}

func (ot ObjectType) MarshalJSON() ([]byte, error) {
	return json.Marshal(ot.String())
}

func RegisterObjectType(ot ObjectType, name string) {
	auditTypeMu.Lock()
	defer auditTypeMu.Unlock()
	objectTypeNames[ot] = name
}

type ActionType int

const (
	ActionTypeCreate ActionType = iota
	ActionTypeRead
	ActionTypeUpdate
	ActionTypeDelete
	ActionTypeRewrap
	ActionTypeRotate
)

var actionTypeNames = map[ActionType]string{
	ActionTypeCreate: "create",
	ActionTypeRead:   "read",
	ActionTypeUpdate: "update",
	ActionTypeDelete: "delete",
	ActionTypeRewrap: "rewrap",
	ActionTypeRotate: "rotate",
}

func (at ActionType) String() string {
	auditTypeMu.RLock()
	name, ok := actionTypeNames[at]
	auditTypeMu.RUnlock()
	if ok {
		return name
	}
	return fmt.Sprintf("action_type_%d", at)
}

func (at ActionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(at.String())
}

func RegisterActionType(at ActionType, name string) {
	auditTypeMu.Lock()
	defer auditTypeMu.Unlock()
	actionTypeNames[at] = name
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

var actionResultNames = map[ActionResult]string{
	ActionResultSuccess:  "success",
	ActionResultFailure:  "failure",
	ActionResultError:    "error",
	ActionResultEncrypt:  "encrypt",
	ActionResultBlock:    "block",
	ActionResultIgnore:   "ignore",
	ActionResultOverride: "override",
	ActionResultCancel:   "cancel",
}

func (ar ActionResult) String() string {
	auditTypeMu.RLock()
	name, ok := actionResultNames[ar]
	auditTypeMu.RUnlock()
	if ok {
		return name
	}
	return fmt.Sprintf("action_result_%d", ar)
}

func (ar ActionResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(ar.String())
}

func RegisterActionResult(ar ActionResult, name string) {
	auditTypeMu.Lock()
	defer auditTypeMu.Unlock()
	actionResultNames[ar] = name
}
