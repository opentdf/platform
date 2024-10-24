package db

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
)

const (
	StateInactive    = "INACTIVE"
	StateActive      = "ACTIVE"
	StateAny         = "ANY"
	StateUnspecified = "UNSPECIFIED"
)

type PolicyDBClient struct {
	*db.Client
	logger *logger.Logger
	*Queries
}

func (c *PolicyDBClient) RunInTx(ctx context.Context, f func(txClient *PolicyDBClient) error) error {
	// todo: could abstract Pgx.Tx to a common interface
	tx, err := c.Client.Pgx.Begin(ctx)
	if err != nil {
		return err
	}

	txClient := &PolicyDBClient{c.Client, c.logger, c.Queries.WithTx(tx)}

	err = f(txClient)
	if err != nil {
		return tx.Rollback(ctx)
	}

	return tx.Commit(ctx)
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
