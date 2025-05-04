package util

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type FullyQualifiedResourceMappingGroup struct {
	Fqn       string
	Namespace string
	GroupName string
}

type FullyQualifiedRegisteredResourceValue struct {
	Fqn   string
	Name  string
	Value string
}

// Structs and regexes for attribute FQNs
type FullyQualifiedAttribute struct {
	Fqn       string
	Namespace string
	Name      string
	Value     string
}

var (
	ErrInvalidFQNFormat = errors.New("error: invalid FQN format")

	// Regex for attribute value FQN format: https://<namespace>/attr/<name>/value/<value>
	// The $ at the end ensures no extra segments after value
	attributeValueFQNRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>[^\/]+)\/attr\/(?<name>[^\/]+)\/value\/(?<value>[^\/]+)$`,
	)

	// Regex for attribute definition FQN format: https://<namespace>/attr/<name>
	// The $ at the end ensures no extra segments after name
	attributeDefinitionFQNRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>[^\/]+)\/attr\/(?<name>[^\/]+)$`,
	)

	// Regex for just namespace: https://<namespace>
	// Only match exactly https:// followed by a namespace with no forward slashes
	namespaceOnlyRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>[^\/]+)$`,
	)

	// protovalidate already validates the FQN format in the service request
	// for parsing purposes, we can just look for any non-whitespace characters
	// e.g. should be in format of "https://<namespace>/resm/<group name>"
	resourceMappingGroupFqnRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>\S+)\/resm\/(?<groupName>\S+)$`,
	)

	registeredResourceValueFqnRegex = regexp.MustCompile(
		`^https:\/\/reg_res\/(?<name>\S+)\/value\/(?<value>\S+)$`,
	)

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

// todo: is it possible to make this more generic and support all fqn formats?

// ParseResourceMappingGroupFqn parses a resource mapping group FQN string into a FullyQualifiedResourceMappingGroup struct.
// The FQN must be in the format: https://<namespace>/resm/<group name>
func ParseResourceMappingGroupFqn(fqn string) (*FullyQualifiedResourceMappingGroup, error) {
	matches := resourceMappingGroupFqnRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	namespaceIdx := resourceMappingGroupFqnRegex.SubexpIndex("namespace")
	groupNameIdx := resourceMappingGroupFqnRegex.SubexpIndex("groupName")

	if numMatches < namespaceIdx || numMatches < groupNameIdx {
		return nil, errors.New("error: valid FQN format of https://<namespace>/resm/<group name> must be provided")
	}

	ns := matches[namespaceIdx]
	groupName := matches[groupNameIdx]

	isValid := validNamespaceRegex.MatchString(ns) && validObjectNameRegex.MatchString(groupName)
	if !isValid {
		return nil, fmt.Errorf("%w: found namespace %s with group name %s", ErrInvalidFQNFormat, ns, groupName)
	}

	return &FullyQualifiedResourceMappingGroup{
		Fqn:       fqn,
		Namespace: ns,
		GroupName: groupName,
	}, nil
}

// ParseRegisteredResourceValueFqn parses a registered resource value FQN string into a FullyQualifiedRegisteredResourceValue struct.
// The FQN must be in the format: https://reg_res/<name>/value/<value>
func ParseRegisteredResourceValueFqn(fqn string) (*FullyQualifiedRegisteredResourceValue, error) {
	matches := registeredResourceValueFqnRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	nameIdx := registeredResourceValueFqnRegex.SubexpIndex("name")
	valueIdx := registeredResourceValueFqnRegex.SubexpIndex("value")

	if numMatches < nameIdx || numMatches < valueIdx {
		return nil, fmt.Errorf("%w: valid FQN format of https://reg_res/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
	}

	name := matches[nameIdx]
	value := matches[valueIdx]
	isValid := validObjectNameRegex.MatchString(name) && validObjectNameRegex.MatchString(value)
	if !isValid {
		return nil, fmt.Errorf("%w: found name %s with value %s", ErrInvalidFQNFormat, name, value)
	}

	return &FullyQualifiedRegisteredResourceValue{
		Fqn:   fqn,
		Name:  name,
		Value: value,
	}, nil
}

// ParseAttributeFqn parses an attribute FQN string into a FullyQualifiedAttribute struct.
// The FQN can be:
// - a namespace only FQN (https://<namespace>)
// - a definition FQN (https://<namespace>/attr/<name>)
// - a value FQN (https://<namespace>/attr/<name>/value/<value>)
func ParseAttributeFqn(fqn string) (*FullyQualifiedAttribute, error) {
	parsed := &FullyQualifiedAttribute{
		Fqn: fqn,
	}

	// First try to match against the attribute value pattern
	valueMatches := attributeValueFQNRegex.FindStringSubmatch(fqn)
	if len(valueMatches) > 0 {
		namespaceIdx := attributeValueFQNRegex.SubexpIndex("namespace")
		nameIdx := attributeValueFQNRegex.SubexpIndex("name")
		valueIdx := attributeValueFQNRegex.SubexpIndex("value")

		if len(valueMatches) <= namespaceIdx || len(valueMatches) <= nameIdx || len(valueMatches) <= valueIdx {
			return nil, fmt.Errorf("%w: valid attribute value FQN format https://<namespace>/attr/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
		}

		ns := valueMatches[namespaceIdx]
		name := valueMatches[nameIdx]
		value := valueMatches[valueIdx]

		isValid := validNamespaceRegex.MatchString(ns) && validObjectNameRegex.MatchString(name) && validObjectNameRegex.MatchString(value)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s with attribute name %s and value %s", ErrInvalidFQNFormat, ns, name, value)
		}

		parsed.Namespace = ns
		parsed.Name = name
		parsed.Value = value

		return parsed, nil
	}

	// If not a value FQN, try to match against the attribute definition pattern
	defMatches := attributeDefinitionFQNRegex.FindStringSubmatch(fqn)
	if len(defMatches) > 0 {
		namespaceIdx := attributeDefinitionFQNRegex.SubexpIndex("namespace")
		nameIdx := attributeDefinitionFQNRegex.SubexpIndex("name")

		if len(defMatches) <= namespaceIdx || len(defMatches) <= nameIdx {
			return nil, errors.New("error: valid attribute definition FQN format https://<namespace>/attr/<name> must be provided")
		}

		ns := defMatches[namespaceIdx]
		name := defMatches[nameIdx]

		isValid := validNamespaceRegex.MatchString(ns) && validObjectNameRegex.MatchString(name)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s with attribute name %s", ErrInvalidFQNFormat, ns, name)
		}
		parsed.Namespace = ns
		parsed.Name = name

		return parsed, nil
	}

	// If not a definition FQN, try to match against just the namespace
	nsMatches := namespaceOnlyRegex.FindStringSubmatch(fqn)
	if len(nsMatches) > 0 {
		namespaceIdx := namespaceOnlyRegex.SubexpIndex("namespace")

		if len(nsMatches) <= namespaceIdx {
			return nil, errors.New("error: valid namespace FQN format https://<namespace> must be provided")
		}

		ns := nsMatches[namespaceIdx]
		isValid := validNamespaceRegex.MatchString(ns)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s", ErrInvalidFQNFormat, ns)
		}

		parsed.Namespace = ns
		return parsed, nil
	}

	return nil, errors.New("error: invalid attribute FQN format, must be https://<namespace>, https://<namespace>/attr/<name>, or https://<namespace>/attr/<name>/value/<value>")
}

func AttributeFqnBuilder(namespace, name, value string) (string, error) {
	// namespace must be valid
	if !validNamespaceRegex.MatchString(namespace) {
		return "", fmt.Errorf("error: invalid namespace %s", namespace)
	}

	builder := strings.Builder{}
	builder.WriteString("https://")
	builder.WriteString(namespace)

	// if name, must be valid
	if name != "" {
		if !validObjectNameRegex.MatchString(name) {
			return "", fmt.Errorf("error: invalid attribute name %s", name)
		}
		builder.WriteString("/attr/")
		builder.WriteString(name)

		if value != "" {
			if !validObjectNameRegex.MatchString(value) {
				return "", fmt.Errorf("error: invalid attribute value %s", value)
			}
			builder.WriteString("/value/")
			builder.WriteString(value)
		}
	}
	return builder.String(), nil
}
