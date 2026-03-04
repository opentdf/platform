package identifier

import (
	"fmt"
	"regexp"
	"strings"
)

type FullyQualifiedRegisteredResourceValue struct {
	Namespace string
	Name      string
	Value     string
}

// New FQN format: https://<namespace>/rr/<name>/value/<value>
var registeredResourceValueFqnRegex = regexp.MustCompile(
	`^https:\/\/(?P<namespace>[^\/]+)\/rr\/(?P<name>[^\/]+)\/value\/(?P<value>[^\/]+)$`,
)

// Legacy FQN format: https://reg_res/<name>/value/<value>
var legacyRegisteredResourceValueFqnRegex = regexp.MustCompile(
	`^https:\/\/reg_res\/(?P<name>[^\/]+)\/value\/(?P<value>[^\/]+)$`,
)

// matchFqnParts attempts to match fqn against re, extracts named groups, lowercases them,
// and validates name/value with validObjectNameRegex. Returns nil if the regex doesn't match.
func matchFqnParts(re *regexp.Regexp, fqn string, groups []string) (map[string]string, error) {
	matches := re.FindStringSubmatch(fqn)
	if len(matches) == 0 {
		return nil, nil //nolint:nilnil // nil means no match, not an error
	}
	result := make(map[string]string, len(groups))
	for _, g := range groups {
		idx := re.SubexpIndex(g)
		if idx == -1 || idx >= len(matches) {
			return nil, fmt.Errorf("%w: missing group %s", ErrInvalidFQNFormat, g)
		}
		result[g] = strings.ToLower(matches[idx])
	}
	name, value := result["name"], result["value"]
	if !validObjectNameRegex.MatchString(name) || !validObjectNameRegex.MatchString(value) {
		return nil, fmt.Errorf("%w: found name %s with value %s", ErrInvalidFQNFormat, name, value)
	}
	return result, nil
}

// parseRegisteredResourceValueFqn parses a registered resource value FQN string into a FullyQualifiedRegisteredResourceValue struct.
// Supports both the new format: https://<namespace>/rr/<name>/value/<value>
// and the legacy format: https://reg_res/<name>/value/<value>
func parseRegisteredResourceValueFqn(fqn string) (*FullyQualifiedRegisteredResourceValue, error) {
	// Try new format: https://<namespace>/rr/<name>/value/<value>
	if parts, err := matchFqnParts(registeredResourceValueFqnRegex, fqn, []string{"namespace", "name", "value"}); err != nil {
		return nil, err
	} else if parts != nil {
		return &FullyQualifiedRegisteredResourceValue{Namespace: parts["namespace"], Name: parts["name"], Value: parts["value"]}, nil
	}

	// Try legacy format: https://reg_res/<name>/value/<value>
	if parts, err := matchFqnParts(legacyRegisteredResourceValueFqnRegex, fqn, []string{"name", "value"}); err != nil {
		return nil, err
	} else if parts != nil {
		return &FullyQualifiedRegisteredResourceValue{Name: parts["name"], Value: parts["value"]}, nil
	}

	return nil, fmt.Errorf("%w: FQN must be in format https://<namespace>/rr/<name>/value/<value>", ErrInvalidFQNFormat)
}

// Implementing FullyQualified interface for FullyQualifiedRegisteredResourceValue
func (rrv *FullyQualifiedRegisteredResourceValue) FQN() string {
	builder := strings.Builder{}
	if rrv.Namespace != "" {
		builder.WriteString("https://")
		builder.WriteString(rrv.Namespace)
		builder.WriteString("/rr/")
	} else {
		// Legacy format for backward compatibility
		builder.WriteString("https://reg_res/")
	}
	builder.WriteString(rrv.Name)
	builder.WriteString("/value/")
	builder.WriteString(rrv.Value)
	return strings.ToLower(builder.String())
}

func (rrv *FullyQualifiedRegisteredResourceValue) Validate() error {
	if !validObjectNameRegex.MatchString(rrv.Name) {
		return fmt.Errorf("%w: invalid resource name format %s", ErrInvalidFQNFormat, rrv.Name)
	}
	if !validObjectNameRegex.MatchString(rrv.Value) {
		return fmt.Errorf("%w: invalid resource value format %s", ErrInvalidFQNFormat, rrv.Value)
	}
	return nil
}
