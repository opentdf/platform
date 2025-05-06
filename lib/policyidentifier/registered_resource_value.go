package policyidentifier

import (
	"fmt"
	"regexp"
	"strings"
)

type FullyQualifiedRegisteredResourceValue struct {
	Name  string
	Value string
}

// protovalidate already validates the FQN format in the service request
// for parsing purposes, we can just look for any non-whitespace characters
// e.g. should be in format of "https://reg_res/<name>/value/<value>"
var registeredResourceValueFqnRegex = regexp.MustCompile(
	`^https:\/\/reg_res\/(?<name>\S+)\/value\/(?<value>\S+)$`,
)

// parseRegisteredResourceValueFqn parses a registered resource value FQN string into a FullyQualifiedRegisteredResourceValue struct.
// The FQN must be in the format: https://reg_res/<name>/value/<value>
func parseRegisteredResourceValueFqn(fqn string) (*FullyQualifiedRegisteredResourceValue, error) {
	matches := registeredResourceValueFqnRegex.FindStringSubmatch(fqn)

	// Check if we have matches first
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: FQN must be in format https://reg_res/<name>/value/<value>", ErrInvalidFQNFormat)
	}

	nameIdx := registeredResourceValueFqnRegex.SubexpIndex("name")
	valueIdx := registeredResourceValueFqnRegex.SubexpIndex("value")

	if nameIdx == -1 || valueIdx == -1 || len(matches) <= nameIdx || len(matches) <= valueIdx {
		return nil, fmt.Errorf("%w: valid FQN format of https://reg_res/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
	}

	name := strings.ToLower(matches[nameIdx])
	value := strings.ToLower(matches[valueIdx])
	isValid := validObjectNameRegex.MatchString(name) && validObjectNameRegex.MatchString(value)
	if !isValid {
		return nil, fmt.Errorf("%w: found name %s with value %s", ErrInvalidFQNFormat, name, value)
	}

	return &FullyQualifiedRegisteredResourceValue{
		Name:  name,
		Value: value,
	}, nil
}

// Implementing FullyQualified interface for FullyQualifiedRegisteredResourceValue
func (rrv *FullyQualifiedRegisteredResourceValue) FQN() string {
	builder := strings.Builder{}
	builder.WriteString("https://reg_res/")
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
