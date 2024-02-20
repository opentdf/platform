package services

import (
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/sdk/common"
)

func GetDbStateTypeTransformedEnum(state common.ActiveStateEnum) string {
	switch state.String() {
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE.String():
		return db.StateActive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE.String():
		return db.StateInactive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY.String():
		return db.StateAny
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED.String():
		return db.StateActive
	default:
		return db.StateActive
	}
}
