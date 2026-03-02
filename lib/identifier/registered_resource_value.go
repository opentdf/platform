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

// parseRegisteredResourceValueFqn parses a registered resource value FQN string into a FullyQualifiedRegisteredResourceValue struct.
// Supports both the new format: https://<namespace>/rr/<name>/value/<value>
// and the legacy format: https://reg_res/<name>/value/<value>
func parseRegisteredResourceValueFqn(fqn string) (*FullyQualifiedRegisteredResourceValue, error) {
	// Try new format first
	matches := registeredResourceValueFqnRegex.FindStringSubmatch(fqn)
	if len(matches) > 0 {
		namespaceIdx := registeredResourceValueFqnRegex.SubexpIndex("namespace")
		nameIdx := registeredResourceValueFqnRegex.SubexpIndex("name")
		valueIdx := registeredResourceValueFqnRegex.SubexpIndex("value")

		if namespaceIdx == -1 || nameIdx == -1 || valueIdx == -1 || len(matches) <= namespaceIdx || len(matches) <= nameIdx || len(matches) <= valueIdx {
			return nil, fmt.Errorf("%w: valid FQN format of https://<namespace>/rr/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
		}

		namespace := strings.ToLower(matches[namespaceIdx])
		name := strings.ToLower(matches[nameIdx])
		value := strings.ToLower(matches[valueIdx])

		if !validObjectNameRegex.MatchString(name) || !validObjectNameRegex.MatchString(value) {
			return nil, fmt.Errorf("%w: found name %s with value %s", ErrInvalidFQNFormat, name, value)
		}

		return &FullyQualifiedRegisteredResourceValue{
			Namespace: namespace,
			Name:      name,
			Value:     value,
		}, nil
	}

	// Try legacy format
	matches = legacyRegisteredResourceValueFqnRegex.FindStringSubmatch(fqn)
	if len(matches) > 0 {
		nameIdx := legacyRegisteredResourceValueFqnRegex.SubexpIndex("name")
		valueIdx := legacyRegisteredResourceValueFqnRegex.SubexpIndex("value")

		if nameIdx == -1 || valueIdx == -1 || len(matches) <= nameIdx || len(matches) <= valueIdx {
			return nil, fmt.Errorf("%w: valid FQN format of https://reg_res/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
		}

		name := strings.ToLower(matches[nameIdx])
		value := strings.ToLower(matches[valueIdx])

		if !validObjectNameRegex.MatchString(name) || !validObjectNameRegex.MatchString(value) {
			return nil, fmt.Errorf("%w: found name %s with value %s", ErrInvalidFQNFormat, name, value)
		}

		return &FullyQualifiedRegisteredResourceValue{
			Name:  name,
			Value: value,
		}, nil
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
