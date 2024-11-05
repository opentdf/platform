package db

import (
	"context"

	"github.com/jackc/pgx/v5"
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

func (c *PolicyDBClient) BeginTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := c.Client.Pgx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (c *PolicyDBClient) WithTx(tx pgx.Tx) *PolicyDBClient {
	return &PolicyDBClient{c.Client, c.logger, c.Queries.WithTx(tx)}
}

func NewClient(c *db.Client, logger *logger.Logger) PolicyDBClient {
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
