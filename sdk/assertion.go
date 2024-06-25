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
	return [...]string{
		"TDO",
		"PAYL",
		"EXPLICIT",
	}[s]
}

// AppliesToState - Custom type to hold value for the assertion ranging from 0-1
type AppliesToState uint

const (
	encrypted AppliesToState = iota
	unencrypted
)

func (a AppliesToState) String() string {
	return [...]string{
		"encrypted",
		"unencrypted"}[a]
}

// StatementFormat - Custom type to hold value for the assertion ranging from 0-1
type StatementFormat uint

const (
	ReferenceStatement StatementFormat = iota
	StructuredStatement
	StringStatement
	Base64BinaryStatement
	XMLBase64
	HandlingStatement
	StringType
)

func (s StatementFormat) String() string {
	return [...]string{
		"ReferenceStatement",
		"StructuredStatement",
		"StringStatement",
		"Base64BinaryStatement",
		"XMLBase64",
		"HandlingStatement",
		"String"}[s]
}

// BindingMethod -  Custom type to hold value for the binding method from 0
type BindingMethod uint

const (
	JWT BindingMethod = iota
)

func (b BindingMethod) String() string {
	return [...]string{
		"jwt",
	}[b]
}
