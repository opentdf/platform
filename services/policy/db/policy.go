package db

import (
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/services/internal/db"
)

const (
	StateInactive    = "INACTIVE"
	StateActive      = "ACTIVE"
	StateAny         = "ANY"
	StateUnspecified = "UNSPECIFIED"
)

type PolicyDBClient struct {
	db.Client
}

var (
	TableAttributes                    = "attribute_definitions"
	TableAttributeValues               = "attribute_values"
	TableValueMembers                  = "attribute_value_members"
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
	ValueMembers                  db.Table
	Namespaces                    db.Table
	AttrFqn                       db.Table
	AttributeKeyAccessGrants      db.Table
	AttributeValueKeyAccessGrants db.Table
	ResourceMappings              db.Table
	SubjectMappings               db.Table
	SubjectConditionSet           db.Table
}

func NewClient(c db.Client) *PolicyDBClient {
	Tables.Attributes = db.NewTable(TableAttributes)
	Tables.AttributeValues = db.NewTable(TableAttributeValues)
	Tables.ValueMembers = db.NewTable(TableValueMembers)
	Tables.Namespaces = db.NewTable(TableNamespaces)
	Tables.AttrFqn = db.NewTable(TableAttrFqn)
	Tables.AttributeKeyAccessGrants = db.NewTable(TableAttributeKeyAccessGrants)
	Tables.AttributeValueKeyAccessGrants = db.NewTable(TableAttributeValueKeyAccessGrants)
	Tables.ResourceMappings = db.NewTable(TableResourceMappings)
	Tables.SubjectMappings = db.NewTable(TableSubjectMappings)
	Tables.SubjectConditionSet = db.NewTable(TableSubjectConditionSet)

	return &PolicyDBClient{c}
}

func GetDBStateTypeTransformedEnum(state common.ActiveStateEnum) string {
	switch state.String() {
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE.String():
		return StateActive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE.String():
		return StateInactive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY.String():
		return StateAny
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED.String():
		return StateActive
	default:
		return StateActive
	}
}
