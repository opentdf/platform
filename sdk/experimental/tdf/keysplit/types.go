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
	// Keys lists every KAS key that can unwrap this split; any one of
	// them suffices.
	//
	// This replaces the URL list that used to pair with a result-wide,
	// URL-keyed key map. One KAS can hold several keys for one split --
	// different key IDs, possibly different algorithms -- and a map
	// keyed by URL silently dropped all but one of them.
	Keys []KASPublicKey
}

// SplitResult contains all splits and their associated KAS public keys
type SplitResult struct {
	// Splits contains all the generated key splits
	Splits []Split
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
//
// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
type GrantLevel int

const (
	// ValueLevel indicates grants defined on the attribute value (most specific)
	//
	// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
	ValueLevel GrantLevel = iota
	// DefinitionLevel indicates grants defined on the attribute definition
	//
	// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
	DefinitionLevel
	// NamespaceLevel indicates grants defined on the attribute namespace (least specific)
	//
	// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
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
//
// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
type AttributeGrant struct {
	// Level indicates where this grant was found in the hierarchy
	Level GrantLevel
	// Attribute is the attribute definition this grant applies to
	Attribute *policy.Attribute
	// KASGrants contains the resolved KAS server information
	KASGrants []KASGrant
}

// KASGrant represents a single KAS server grant with its public key
//
// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
type KASGrant struct {
	// URL of the KAS server
	URL string
	// PublicKey contains the key information
	PublicKey *policy.SimpleKasPublicKey
}

// AttributeClause groups attribute values by their definition and rule
//
// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
type AttributeClause struct {
	// Definition is the attribute definition
	Definition *policy.Attribute
	// Values are all values for this attribute
	Values []*policy.Value
	// Rule specifies how values should be combined (allOf, anyOf, hierarchy)
	Rule policy.AttributeRuleTypeEnum
}

// BooleanExpression represents the complete attribute policy as clauses
//
// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
type BooleanExpression struct {
	// Clauses contains all attribute clauses (ANDed together)
	Clauses []AttributeClause
}

// SplitAssignment maps a split ID to its KAS assignments and keys
//
// Deprecated: no longer produced by this package; retained so dependent code keeps compiling.
type SplitAssignment struct {
	// SplitID is the unique identifier for this split
	SplitID string
	// KASURLs lists all KAS servers for this split
	KASURLs []string
	// Keys maps KAS URLs to their public key information
	Keys map[string]*policy.SimpleKasPublicKey
}
