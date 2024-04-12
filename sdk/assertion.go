package sdk

// AssertionType - Custom type to hold value for the assertion ranging from 0-1
type AssertionType uint

const (
	handlingAssertion AssertionType = iota
	baseAssertion
)

func (a AssertionType) String() string {
	return [...]string{"Handling", "Base"}[a]
}

// Scope - Custom type to hold value for the assertion ranging from 0-1
type Scope uint

const (
	trustedDataObj Scope = iota
	payload
	explicit
)

func (s Scope) String() string {
	return [...]string{"TDO", "PAYL", "EXPLICIT"}[s]
}

// AppliesToState - Custom type to hold value for the assertion ranging from 0-1
type AppliesToState uint

const (
	encrypted AppliesToState = iota
	unencrypted
)

func (a AppliesToState) String() string {
	return [...]string{"encrypted", "unencrypted"}[a]
}

// StatementType - Custom type to hold value for the assertion ranging from 0-1
type StatementType uint

const (
	ReferenceStatement StatementType = iota
	StructuredStatement
	StringStatement
	Base64BinaryStatement
	XMLBase64
	HandlingStatement
	StringType
)

func (s StatementType) String() string {
	return [...]string{"ReferenceStatement", "StructuredStatement", "StringStatement",
		"Base64BinaryStatement", "XMLBase64", "HandlingStatement", "String"}[s]
}
