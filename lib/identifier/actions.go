package identifier

// PolicyActionStandard is the type for standard policy action names.
type PolicyActionStandard string

const (
	// PolicyActionNameCreate is the stored name of the standard 'create' action.
	PolicyActionNameCreate PolicyActionStandard = "create"
	// PolicyActionNameRead is the stored name of the standard 'read' action.
	PolicyActionNameRead PolicyActionStandard = "read"
	// PolicyActionNameUpdate is the stored name of the standard 'update' action.
	PolicyActionNameUpdate PolicyActionStandard = "update"
	// PolicyActionNameDelete is the stored name of the standard 'delete' action.
	PolicyActionNameDelete PolicyActionStandard = "delete"
)

// String returns the string representation of the action name.
func (a PolicyActionStandard) String() string {
	return string(a)
}

// IsValid reports whether a is one of the four standard action names.
func (a PolicyActionStandard) IsValid() bool {
	switch a {
	case PolicyActionNameCreate, PolicyActionNameRead, PolicyActionNameUpdate, PolicyActionNameDelete:
		return true
	}
	return false
}
