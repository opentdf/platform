package sdk

// Standard policy action name constants (CRUD).
// These values MUST match the canonical definitions in:
//   - service/policy/db/actions.go (ActionStandard type + ActionCreate/Read/Update/Delete)
//   - service/policy/actions/actions.go (ActionNameCreate/Read/Update/Delete re-exports)
//
// They are duplicated here so SDK consumers can reference standard action names
// without importing the heavy service module.
const (
	ActionNameCreate = "create"
	ActionNameRead   = "read"
	ActionNameUpdate = "update"
	ActionNameDelete = "delete"
)
