package authorizationv2

import (
	"github.com/opentdf/platform/protocol/go/policy"
)

// ForAction returns an Action with the given name, for use as the Action field
// of a GetDecisionRequest. It lets callers avoid importing the policy package
// directly at the call site.
func ForAction(name string) *policy.Action {
	return &policy.Action{
		Name: name,
	}
}
