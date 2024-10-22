package db

import (
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
)

const (
	stateInactive    transformedState = "INACTIVE"
	stateActive      transformedState = "ACTIVE"
	stateAny         transformedState = "ANY"
	stateUnspecified transformedState = "UNSPECIFIED"
)

type transformedState string

type PolicyDBClient struct {
	*db.Client
	logger *logger.Logger
	*Queries
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
	TableKeyAccessServerRegistry       = "key_access_servers"
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
	KeyAccessServerRegistry       db.Table
}

func NewClient(c *db.Client, logger *logger.Logger) PolicyDBClient {
	t := db.NewTable(c.Schema())
	Tables.Attributes = t(TableAttributes)
	Tables.AttributeValues = t(TableAttributeValues)
	Tables.Namespaces = t(TableNamespaces)
	Tables.AttrFqn = t(TableAttrFqn)
	Tables.AttributeKeyAccessGrants = t(TableAttributeKeyAccessGrants)
	Tables.AttributeValueKeyAccessGrants = t(TableAttributeValueKeyAccessGrants)
	Tables.ResourceMappings = t(TableResourceMappings)
	Tables.SubjectMappings = t(TableSubjectMappings)
	Tables.SubjectConditionSet = t(TableSubjectConditionSet)
	Tables.KeyAccessServerRegistry = t(TableKeyAccessServerRegistry)

	return PolicyDBClient{c, logger, New(c.Pgx)}
}

func getDBStateTypeTransformedEnum(state common.ActiveStateEnum) transformedState {
	switch state.String() {
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE.String():
		return stateActive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE.String():
		return stateInactive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY.String():
		return stateAny
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED.String():
		return stateActive
	default:
		return stateActive
	}
}
