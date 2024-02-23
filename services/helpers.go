package services

import (
	"github.com/opentdf/platform/protocol/go/common"
	policydb "github.com/opentdf/platform/services/policy/db"
)

func GetDbStateTypeTransformedEnum(state common.ActiveStateEnum) string {
	switch state {
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE:
		return policydb.StateActive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE:
		return policydb.StateInactive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY:
		return policydb.StateAny
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED:
		return policydb.StateActive
	default:
		return policydb.StateActive
	}
}
