package services

import (
	"github.com/opentdf/opentdf-v2-poc/protocol/go/common"
	policydb "github.com/opentdf/opentdf-v2-poc/services/policy/db"
)

func GetDbStateTypeTransformedEnum(state common.ActiveStateEnum) string {
	switch state.String() {
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE.String():
		return policydb.StateActive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE.String():
		return policydb.StateInactive
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY.String():
		return policydb.StateAny
	case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED.String():
		return policydb.StateActive
	default:
		return policydb.StateActive
	}
}
