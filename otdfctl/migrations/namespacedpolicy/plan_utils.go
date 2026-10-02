package namespacedpolicy

import (
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
)

func objectIDSet[T interface{ GetId() string }](items []T) map[string]struct{} {
	ids := make(map[string]struct{}, len(items))
	for _, item := range items {
		if id := item.GetId(); id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}

func isStandardAction(action *policy.Action) bool {
	if action == nil {
		return false
	}
	if action.GetStandard() != policy.Action_STANDARD_ACTION_UNSPECIFIED {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(action.GetName())) {
	case "create", "read", "update", "delete":
		return true
	default:
		return false
	}
}
