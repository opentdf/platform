package services

import (
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
)

func GetDbStateEnum(state common.StateTypeEnum) string {
	switch state.String() {
	case common.StateTypeEnum_STATE_TYPE_ENUM_ACTIVE.String():
		return db.StateActive
	case common.StateTypeEnum_STATE_TYPE_ENUM_INACTIVE.String():
		return db.StateInactive
	case common.StateTypeEnum_STATE_TYPE_ENUM_ANY.String():
		return db.StateAny
	case common.StateTypeEnum_STATE_TYPE_ENUM_UNSPECIFIED.String():
		return db.StateActive
	default:
		return db.StateActive
	}
}
