// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import (
	"github.com/opentdf/platform/protocol/go/policy"
)

// Split represents a single cryptographic key split with its KAS assignments
type Split struct {
	// ID is a unique identifier for this split (empty if only one split)
	ID string
	// Data contains the actual split key bytes
	Data []byte
	// KASURLs lists all KAS servers that can decrypt this split
	KASURLs []string
}

// SplitResult contains all splits and their associated KAS public keys
type SplitResult struct {
	// Splits contains all the generated key splits
	Splits []Split
	// KASPublicKeys maps KAS URLs to their public key information
	KASPublicKeys map[string]KASPublicKey
}

// KASPublicKey contains public key information extracted from policy
type KASPublicKey struct {
	// URL of the KAS server
	URL string
	// KID is the key identifier
	KID string
	// PEM is the public key in PEM format
	PEM string
	// Algorithm specifies the key algorithm (e.g., "rsa", "ec")
	Algorithm string
}

// GrantLevel indicates where a KAS grant is defined in the attribute hierarchy
type GrantLevel int

const (
	// ValueLevel indicates grants defined on the attribute value (most specific)
	ValueLevel GrantLevel = iota
	// DefinitionLevel indicates grants defined on the attribute definition
	DefinitionLevel
	// NamespaceLevel indicates grants defined on the attribute namespace (least specific)
	NamespaceLevel
)

func (gl GrantLevel) String() string {
	switch gl {
	case ValueLevel:
		return "value"
	case DefinitionLevel:
		return "definition"
	case NamespaceLevel:
		return "namespace"
	default:
		return "unknown"
	}
}

// AttributeGrant represents KAS grants resolved for a specific attribute
type AttributeGrant struct {
	// Level indicates where this grant was found in the hierarchy
	Level GrantLevel
	// Attribute is the attribute definition this grant applies to
	Attribute *policy.Attribute
	// KASGrants contains the resolved KAS server information
	KASGrants []KASGrant
}

// KASGrant represents a single KAS server grant with its public key
type KASGrant struct {
	// URL of the KAS server
	URL string
	// PublicKey contains the key information
	PublicKey *policy.SimpleKasPublicKey
}

// AttributeClause groups attribute values by their definition and rule
type AttributeClause struct {
	// Definition is the attribute definition
	Definition *policy.Attribute
	// Values are all values for this attribute
	Values []*policy.Value
	// Rule specifies how values should be combined (allOf, anyOf, hierarchy)
	Rule policy.AttributeRuleTypeEnum
}

// BooleanExpression represents the complete attribute policy as clauses
type BooleanExpression struct {
	// Clauses contains all attribute clauses (ANDed together)
	Clauses []AttributeClause
}

// SplitAssignment maps a split ID to its KAS assignments and keys
type SplitAssignment struct {
	// SplitID is the unique identifier for this split
	SplitID string
	// KASURLs lists all KAS servers for this split
	KASURLs []string
	// Keys maps KAS URLs to their public key information
	Keys map[string]*policy.SimpleKasPublicKey
}
