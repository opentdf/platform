package dynamicentitlement

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/lib/identifier"
)

// DynamicOperator enumerates the comparison semantics for dynamic, definition-level
// entitlement. Unlike policy.SubjectMappingOperatorEnum — whose right-hand operand is a
// STATIC list authored into policy (policy.Condition.subject_external_values) — a
// DynamicOperator's right-hand operand is supplied at decision time from the resource's
// attribute value segment. Each value below is the inversion of its static counterpart.
type DynamicOperator int

const (
	// OperatorUnspecified is the zero value and is always an error to evaluate.
	OperatorUnspecified DynamicOperator = iota
	// ResourceValueIn is true when the resource value segment exactly matches one of the
	// values produced by resolving the selector against the entity representation. It is
	// the inversion of SUBJECT_MAPPING_OPERATOR_ENUM_IN.
	ResourceValueIn
	// ResourceValueInContains is true when any selector-resolved entity value contains
	// the resource value segment as a substring. It is the inversion of
	// SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS.
	ResourceValueInContains
)

func (o DynamicOperator) String() string {
	switch o {
	case ResourceValueIn:
		return "RESOURCE_VALUE_IN"
	case ResourceValueInContains:
		return "RESOURCE_VALUE_IN_CONTAINS"
	case OperatorUnspecified:
		return "UNSPECIFIED"
	default:
		return fmt.Sprintf("DynamicOperator(%d)", int(o))
	}
}

// Canonicalizer normalizes a single identifier token prior to comparison. External
// systems (EHRs, IdPs) frequently disagree with policy on case and surrounding
// whitespace; without a canonicalization step the same logical ID fails to match. This
// is the normalization/canonicalization concern raised by @biscoe916 on ADR#266. The
// default lowercases and trims; deployments needing more (e.g. Unicode NFC folding)
// supply their own.
type Canonicalizer func(string) string

// DefaultCanonicalizer lowercases and trims surrounding whitespace. It matches the
// case-insensitivity that lib/identifier already applies to FQNs (identifier.Parse
// lowercases), so the resource side and entity side land in the same space.
func DefaultCanonicalizer(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// fqnAmbiguousChars are characters that must never appear in an attribute value segment
// because they collide with FQN structure or URL encoding (raised by @jentfoo on
// ADR#266). Even if the value character set is loosened for dynamic values — e.g. to
// admit '@' for email-like identifiers — these remain forbidden as the safety floor.
const fqnAmbiguousChars = "/.%\x00"

// maxASCII is the highest ASCII code point; runes above it are rejected in value
// segments to avoid Unicode confusables and normalization hazards.
const maxASCII = 127

var (
	// ErrUnspecifiedOperator indicates a mapping was evaluated with the zero operator.
	ErrUnspecifiedOperator = errors.New("dynamicentitlement: unspecified dynamic operator")
	// ErrUnsupportedOperator indicates an operator value with no evaluation semantics.
	ErrUnsupportedOperator = errors.New("dynamicentitlement: unsupported dynamic operator")
	// ErrAmbiguousValueSegment indicates a value segment contains characters that are
	// unsafe in an attribute value FQN.
	ErrAmbiguousValueSegment = errors.New("dynamicentitlement: attribute value segment contains FQN-ambiguous characters")
	// ErrNotValueFQN indicates an FQN that is not a concrete attribute value FQN.
	ErrNotValueFQN = errors.New("dynamicentitlement: not a value FQN")
)

// parseResourceValue splits a concrete attribute value FQN into its parent definition
// FQN and the value segment, reusing lib/identifier so the spike inherits the exact FQN
// grammar (and character-set validation) used by policy today. Both returned strings are
// lowercased, matching identifier.Parse behavior.
func parseResourceValue(valueFQN string) (string, string, error) {
	parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](valueFQN)
	if err != nil {
		return "", "", fmt.Errorf("parsing resource value FQN %q: %w", valueFQN, err)
	}
	if parsed.Value == "" {
		return "", "", fmt.Errorf("%w: %q", ErrNotValueFQN, valueFQN)
	}
	def := &identifier.FullyQualifiedAttribute{Namespace: parsed.Namespace, Name: parsed.Name}
	return def.FQN(), parsed.Value, nil
}

// validateValueSegment is the reusable safety floor for a value segment. lib/identifier
// already enforces a strict alphanumeric+[-_] set today; this function expresses the
// minimum that must survive ANY future loosening of that set (e.g. to support emails or
// dotted IDs): reject FQN-structural characters, percent-encoding, NUL, and non-ASCII.
func validateValueSegment(segment string) error {
	if segment == "" {
		return fmt.Errorf("%w: empty segment", ErrAmbiguousValueSegment)
	}
	if strings.ContainsAny(segment, fqnAmbiguousChars) {
		return fmt.Errorf("%w: %q", ErrAmbiguousValueSegment, segment)
	}
	for _, r := range segment {
		if r > maxASCII {
			return fmt.Errorf("%w: non-ASCII rune in %q", ErrAmbiguousValueSegment, segment)
		}
	}
	return nil
}

// evaluateDynamicMatch reports whether resourceSegment is entitled given the values
// produced by resolving selector against the (already flattened) entity, under the
// supplied operator. canon is applied to both sides before comparison; a nil canon falls
// back to DefaultCanonicalizer.
//
// This is the single shared mechanic every option in the spike depends on.
func evaluateDynamicMatch(op DynamicOperator, entity flattening.Flattened, selector, resourceSegment string, canon Canonicalizer) (bool, error) {
	if canon == nil {
		canon = DefaultCanonicalizer
	}
	entityValues := flattening.GetFromFlattened(entity, selector)
	target := canon(resourceSegment)

	switch op {
	case ResourceValueIn:
		for _, ev := range entityValues {
			if canon(fmt.Sprintf("%v", ev)) == target {
				return true, nil
			}
		}
		return false, nil
	case ResourceValueInContains:
		for _, ev := range entityValues {
			if strings.Contains(canon(fmt.Sprintf("%v", ev)), target) {
				return true, nil
			}
		}
		return false, nil
	case OperatorUnspecified:
		return false, ErrUnspecifiedOperator
	default:
		return false, fmt.Errorf("%w: %s", ErrUnsupportedOperator, op)
	}
}
