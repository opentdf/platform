package db

import (
	"context"
	"fmt"

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

type ListConfig struct {
	limitDefault int32
	limitMax     int32
}

type PolicyDBClient struct {
	*db.Client
	logger *logger.Logger
	*Queries
	listCfg ListConfig
}

func NewClient(c *db.Client, logger *logger.Logger, configuredListLimitMax, configuredListLimitDefault int32) PolicyDBClient {
	return PolicyDBClient{c, logger, New(c.Pgx), ListConfig{limitDefault: configuredListLimitDefault, limitMax: configuredListLimitMax}}
}

func (c *PolicyDBClient) RunInTx(ctx context.Context, query func(txClient *PolicyDBClient) error) error {
	tx, err := c.Client.Pgx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin DB transaction: %w", err)
	}
	//nolint:errcheck // ignore error per sqlc docs https://docs.sqlc.dev/en/stable/howto/transactions.html
	defer tx.Rollback(ctx)

	txClient := &PolicyDBClient{c.Client, c.logger, c.Queries.WithTx(tx), c.listCfg}

	err = query(txClient)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
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
