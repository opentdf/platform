package audit

type ObjectType int

const (
	ObjectTypeSubjectMapping ObjectType = iota
	ObjectTypeResourceMapping
	ObjectTypeAttributeDefinition
	ObjectTypeAttributeValue
	ObjectTypeNamespace
	ObjectTypeConditionSet
	ObjectTypeKasRegistry
	ObjectTypeKasAttributeDefinitionAssignment
	ObjectTypeKasAttributeValueAssignment
	ObjectTypeKeyObject
	ObjectTypeEntityObject
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
		"kas_attribute_definition_assignment",
		"kas_attribute_value_assignment",
		"key_object",
		"entity_object",
	}[ot]
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
