package sdk

import "github.com/opentdf/platform/lib/identifier"

// Standard policy action name constants.
// Canonical definitions live in github.com/opentdf/platform/lib/identifier.
const (
	ActionNameCreate = string(identifier.PolicyActionNameCreate)
	ActionNameRead   = string(identifier.PolicyActionNameRead)
	ActionNameUpdate = string(identifier.PolicyActionNameUpdate)
	ActionNameDelete = string(identifier.PolicyActionNameDelete)
)
