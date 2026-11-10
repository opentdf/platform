package identifier

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrInvalidFQNFormat   = errors.New("error: invalid FQN format")
	ErrUnsupportedFQNType = errors.New("error: unsupported FQN type")

	// Regex rules for valid object names:
	// - alphanumeric
	// - underscores (not beginning or end)
	// - hyphens (not beginning or end)
	// - 1-253 characters in total, starting and ending with an alphanumeric character
	validObjectNameRegex = regexp.MustCompile(
		`^[a-zA-Z0-9]([a-zA-Z0-9_-]{0,251}[a-zA-Z0-9])?$`,
	)

	// Regex rules for valid namespaces:
	// - alphanumeric
	// - hyphens
	// - periods
	// - 1-253 characters in total, starting and ending with an alphanumeric character
	// - at least one period
	// - at least one alphanumeric character
	// - no consecutive periods or hyphens
	validNamespaceRegex = regexp.MustCompile(
		`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
	)
)

// FullyQualified is an interface for all fully qualified objects.
type FullyQualified interface {
	// FQN builds the FQN identifier string with the object names/values.
	FQN() string
	// Validate checks if the names/values are valid according to the regex rules.
	Validate() error
}

// Parse parses an identifier (FQN) string into a specific type of FullyQualified object
// and validates the overall structure along with each name/value of the object fields.
func Parse[T FullyQualified](identifier string) (T, error) {
	var (
		result T
		ok     bool
		parsed any
		err    error
	)
	identifier = strings.ToLower(identifier)
	// Use type assertion to determine the concrete type and call the appropriate parser
	switch any(result).(type) {
	case *FullyQualifiedAttribute:
		parsed, err = parseAttributeFqn(identifier)
		if err != nil {
			return result, err
		}

	case *FullyQualifiedObligation:
		parsed, err = parseObligationFqn(identifier)
		if err != nil {
			return result, err
		}

	case *FullyQualifiedResourceMappingGroup:
		parsed, err = parseResourceMappingGroupFqn(identifier)
		if err != nil {
			return result, err
		}

	case *FullyQualifiedRegisteredResourceValue:
		parsed, err = parseRegisteredResourceValueFqn(identifier)
		if err != nil {
			return result, err
		}

	default:
		return result, fmt.Errorf("%w: %T", ErrUnsupportedFQNType, result)
	}

	result, ok = parsed.(T)
	if !ok {
		return result, fmt.Errorf("%w: %T", ErrUnsupportedFQNType, result)
	}
	return result, nil
}
