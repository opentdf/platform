package db

import (
	"github.com/opentdf/platform/internal/db"
)

const (
	StateInactive    = "INACTIVE"
	StateActive      = "ACTIVE"
	StateAny         = "ANY"
	StateUnspecified = "UNSPECIFIED"
)

type PolicyDbClient struct {
	db.Client
}

var (
	TableAttributes                    = "attribute_definitions"
	TableAttributeValues               = "attribute_values"
	TableNamespaces                    = "attribute_namespaces"
	TableAttrFqn                       = "attribute_fqns"
	TableAttributeKeyAccessGrants      = "attribute_definition_key_access_grants"
	TableAttributeValueKeyAccessGrants = "attribute_value_key_access_grants"
	TableResourceMappings              = "resource_mappings"
	TableSubjectMappings               = "subject_mappings"
	TableSubjectConditionSet           = "subject_condition_set"
)

var Tables struct {
	Attributes                    db.Table
	AttributeValues               db.Table
	Namespaces                    db.Table
	AttrFqn                       db.Table
	AttributeKeyAccessGrants      db.Table
	AttributeValueKeyAccessGrants db.Table
	ResourceMappings              db.Table
	SubjectMappings               db.Table
	SubjectConditionSet           db.Table
}

func NewClient(c db.Client) *PolicyDbClient {
	Tables.Attributes = db.NewTable(TableAttributes)
	Tables.AttributeValues = db.NewTable(TableAttributeValues)
	Tables.Namespaces = db.NewTable(TableNamespaces)
	Tables.AttrFqn = db.NewTable(TableAttrFqn)
	Tables.AttributeKeyAccessGrants = db.NewTable(TableAttributeKeyAccessGrants)
	Tables.AttributeValueKeyAccessGrants = db.NewTable(TableAttributeValueKeyAccessGrants)
	Tables.ResourceMappings = db.NewTable(TableResourceMappings)
	Tables.SubjectMappings = db.NewTable(TableSubjectMappings)
	Tables.SubjectConditionSet = db.NewTable(TableSubjectConditionSet)

	return &PolicyDbClient{c}
}
