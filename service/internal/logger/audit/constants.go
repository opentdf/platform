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
)

func (o ObjectType) String() string {
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
	}[o]
}

type ActionType int

const (
	ActionTypeCreate ActionType = iota
	ActionTypeUpdate
	ActionTypeDelete
	ActionTypeRewrap
)

func (a ActionType) String() string {
	return [...]string{
		"create",
		"update",
		"delete",
		"rewrap",
	}[a]
}
