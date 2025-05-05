package identifier

import (
	"errors"
	"fmt"
	"regexp"
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
	var result T
	var err error

	// TODO: when URNs are supported, check for URN vs FQN and drive accordingly

	// Check which type T is and call the appropriate parsing function
	switch any(result).(type) {
	case *FullyQualifiedAttribute:
		parsedAttr, parseErr := parseAttributeFqn(identifier)
		if parseErr != nil {
			return result, parseErr
		}
		// Type assertion to convert back to generic type T
		result = any(parsedAttr).(T)

	case *FullyQualifiedResourceMappingGroup:
		parsedRmg, parseErr := parseResourceMappingGroupFqn(identifier)
		if parseErr != nil {
			return result, parseErr
		}
		result = any(parsedRmg).(T)

	case *FullyQualifiedRegisteredResourceValue:
		parsedRrv, parseErr := parseRegisteredResourceValueFqn(identifier)
		if parseErr != nil {
			return result, parseErr
		}
		result = any(parsedRrv).(T)

	default:
		return result, fmt.Errorf("%w: %T", ErrUnsupportedFQNType, result)
	}

	return result, err
}
