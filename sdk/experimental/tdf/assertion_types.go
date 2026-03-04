// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

//go:generate tinyjson -all assertion_types.go

package tdf

// Assertion represents a cryptographically signed assertion in the TDF manifest.
//
// Assertions provide integrity verification and handling instructions that are
// cryptographically bound to the TDF. They cannot be modified or copied to
// another TDF without detection due to the cryptographic binding.
//
// The assertion structure includes:
//   - Metadata: ID, type, scope, and state applicability
//   - Statement: The actual assertion content in structured format
//   - Binding: Cryptographic signature ensuring integrity
//
// Assertions are verified during TDF reading to ensure they haven't been
// tampered with since TDF creation.
type Assertion struct {
	ID             string         `json:"id"`
	Type           AssertionType  `json:"type"`
	Scope          Scope          `json:"scope"`
	AppliesToState AppliesToState `json:"appliesToState,omitempty"`
	Statement      Statement      `json:"statement"`
	Binding        Binding        `json:"binding,omitempty"`
}

// Statement includes information applying to the scope of the assertion.
// It could contain rights, handling instructions, or general metadata.
type Statement struct {
	// Format describes the payload encoding format. (e.g. json)
	Format string `json:"format,omitempty" validate:"required"`
	// Schema describes the schema of the payload. (e.g. tdf)
	Schema string `json:"schema,omitempty" validate:"required"`
	// Value is the payload of the assertion.
	Value string `json:"value,omitempty"  validate:"required"`
}

// Binding enforces cryptographic integrity of the assertion.
// So the can't be modified or copied to another tdf.
type Binding struct {
	// Method used to bind the assertion. (e.g. jws)
	Method string `json:"method,omitempty"`
	// Signature of the assertion.
	Signature string `json:"signature,omitempty"`
}
