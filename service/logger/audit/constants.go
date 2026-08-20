package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
)

var (
	ErrAuditTypeRegistrationSealed = errors.New("audit type registrations are sealed")
	ErrInvalidAuditTypeName        = errors.New("audit type name must not be empty")
	ErrAuditTypeAlreadyRegistered  = errors.New("audit type is already registered")
)

var (
	// auditTypeRegistryMu guards registration only. Name lookups are lock-free:
	// each registry holds an immutable map swapped in via copy-on-write, so String()
	// stays on the hot logging path without contending on a mutex.
	auditTypeRegistryMu    sync.Mutex
	typeRegistrationSealed bool
)

// typeNameRegistry maps audit type values to their emitted names.
type typeNameRegistry[T ~int] struct {
	// fallbackPrefix names values that were never registered, e.g. "object_type_42".
	fallbackPrefix string
	names          atomic.Pointer[map[T]string]
}

func newTypeNameRegistry[T ~int](fallbackPrefix string, defaults map[T]string) *typeNameRegistry[T] {
	r := &typeNameRegistry[T]{fallbackPrefix: fallbackPrefix}
	r.names.Store(&defaults)
	return r
}

func (r *typeNameRegistry[T]) lookup(key T) string {
	if name, ok := (*r.names.Load())[key]; ok {
		return name
	}
	return fmt.Sprintf("%s_%d", r.fallbackPrefix, key)
}

// register associates name with key. Registering a key that already has a
// different name (including a built-in type) is rejected so the emitted audit
// taxonomy cannot be silently changed out from under existing consumers.
// Re-registering an identical name is a no-op.
func (r *typeNameRegistry[T]) register(key T, name string) error {
	if name == "" {
		return ErrInvalidAuditTypeName
	}

	auditTypeRegistryMu.Lock()
	defer auditTypeRegistryMu.Unlock()

	if typeRegistrationSealed {
		return ErrAuditTypeRegistrationSealed
	}

	current := *r.names.Load()
	if existing, ok := current[key]; ok {
		if existing == name {
			return nil
		}
		return fmt.Errorf("%w: %s %d is registered as %q, cannot re-register as %q", ErrAuditTypeAlreadyRegistered, r.fallbackPrefix, key, existing, name)
	}

	updated := make(map[T]string, len(current)+1)
	maps.Copy(updated, current)
	updated[key] = name
	r.names.Store(&updated)

	return nil
}

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
	ObjectTypeDynamicValueMapping
)

var objectTypeNames = newTypeNameRegistry("object_type", map[ObjectType]string{
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
	ObjectTypeDynamicValueMapping:                 "dynamic_value_mapping",
})

func (ot ObjectType) String() string {
	return objectTypeNames.lookup(ot)
}

func (ot ObjectType) MarshalJSON() ([]byte, error) {
	return json.Marshal(ot.String())
}

// RegisterObjectType registers the emitted name for an additional object type.
// It must be called before the platform seals registrations during startup, and
// it cannot rename an already registered type.
func RegisterObjectType(ot ObjectType, name string) error {
	return objectTypeNames.register(ot, name)
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

var actionTypeNames = newTypeNameRegistry("action_type", map[ActionType]string{
	ActionTypeCreate: "create",
	ActionTypeRead:   "read",
	ActionTypeUpdate: "update",
	ActionTypeDelete: "delete",
	ActionTypeRewrap: "rewrap",
	ActionTypeRotate: "rotate",
})

func (at ActionType) String() string {
	return actionTypeNames.lookup(at)
}

func (at ActionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(at.String())
}

// RegisterActionType registers the emitted name for an additional action type.
// It must be called before the platform seals registrations during startup, and
// it cannot rename an already registered type.
func RegisterActionType(at ActionType, name string) error {
	return actionTypeNames.register(at, name)
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

var actionResultNames = newTypeNameRegistry("action_result", map[ActionResult]string{
	ActionResultSuccess:  "success",
	ActionResultFailure:  "failure",
	ActionResultError:    "error",
	ActionResultEncrypt:  "encrypt",
	ActionResultBlock:    "block",
	ActionResultIgnore:   "ignore",
	ActionResultOverride: "override",
	ActionResultCancel:   "cancel",
})

func (ar ActionResult) String() string {
	return actionResultNames.lookup(ar)
}

func (ar ActionResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(ar.String())
}

// RegisterActionResult registers the emitted name for an additional action result.
// It must be called before the platform seals registrations during startup, and
// it cannot rename an already registered result.
func RegisterActionResult(ar ActionResult, name string) error {
	return actionResultNames.register(ar, name)
}

type TypeRegistrations struct {
	ObjectTypes   map[ObjectType]string
	ActionTypes   map[ActionType]string
	ActionResults map[ActionResult]string
}

func ApplyTypeRegistrations(reg TypeRegistrations) error {
	for objectType, name := range reg.ObjectTypes {
		if err := RegisterObjectType(objectType, name); err != nil {
			return err
		}
	}

	for actionType, name := range reg.ActionTypes {
		if err := RegisterActionType(actionType, name); err != nil {
			return err
		}
	}

	for actionResult, name := range reg.ActionResults {
		if err := RegisterActionResult(actionResult, name); err != nil {
			return err
		}
	}

	return nil
}

// SealTypeRegistrations blocks any further audit type registrations. The
// platform calls this during startup once all registrations have been applied.
func SealTypeRegistrations() {
	auditTypeRegistryMu.Lock()
	defer auditTypeRegistryMu.Unlock()
	typeRegistrationSealed = true
}
