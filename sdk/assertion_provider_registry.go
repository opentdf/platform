package sdk

// Assertion Provider Registry

// AssertionRegistry manages and dispatches calls to registered assertion providers.
// It implements both the AssertionBinder and AssertionValidator interfaces,
// allowing it to be used internally for assertion management.
type AssertionRegistry struct {
	binders    []AssertionBinder
	validators []AssertionValidator
}

// newAssertionRegistry creates and initializes a new AssertionRegistry.
func newAssertionRegistry() *AssertionRegistry {
	return &AssertionRegistry{
		binders:    make([]AssertionBinder, 0),
		validators: make([]AssertionValidator, 0),
	}
}

func (r *AssertionRegistry) RegisterValidator(validator AssertionValidator) {
	r.validators = append(r.validators, validator)
}

func (r *AssertionRegistry) RegisterBinder(binder AssertionBinder) {
	r.binders = append(r.binders, binder)
}
