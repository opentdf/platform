package policyidentifier

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Structs and regexes for attribute FQNs
type FullyQualifiedAttribute struct {
	Namespace string
	Name      string
	Value     string
}

var (
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
)

// Implementing FullyQualified interface for FullyQualifiedAttribute
func (attr *FullyQualifiedAttribute) FQN() string {
	builder := strings.Builder{}
	builder.WriteString("https://")
	builder.WriteString(attr.Namespace)

	// if name, must be valid
	if attr.Name != "" {
		builder.WriteString("/attr/")
		builder.WriteString(attr.Name)

		if attr.Value != "" {
			builder.WriteString("/value/")
			builder.WriteString(attr.Value)
		}
	}
	return strings.ToLower(builder.String())
}

func (attr *FullyQualifiedAttribute) Validate() error {
	if !validNamespaceRegex.MatchString(attr.Namespace) {
		return fmt.Errorf("%w: invalid namespace format %s", ErrInvalidFQNFormat, attr.Namespace)
	}

	// Only validate name and value if they are present
	if attr.Name != "" && !validObjectNameRegex.MatchString(attr.Name) {
		return fmt.Errorf("%w: invalid attribute name format %s", ErrInvalidFQNFormat, attr.Name)
	}

	if attr.Value != "" && !validObjectNameRegex.MatchString(attr.Value) {
		return fmt.Errorf("%w: invalid attribute value format %s", ErrInvalidFQNFormat, attr.Value)
	}

	return nil
}

// parseAttributeFqn parses an attribute FQN string into a FullyQualifiedAttribute struct.
// The FQN can be:
// - a namespace only FQN (https://<namespace>)
// - a definition FQN (https://<namespace>/attr/<name>)
// - a value FQN (https://<namespace>/attr/<name>/value/<value>)
func parseAttributeFqn(fqn string) (*FullyQualifiedAttribute, error) {
	parsed := &FullyQualifiedAttribute{}

	// First try to match against the attribute value pattern
	valueMatches := attributeValueFQNRegex.FindStringSubmatch(fqn)
	if len(valueMatches) > 0 {
		namespaceIdx := attributeValueFQNRegex.SubexpIndex("namespace")
		nameIdx := attributeValueFQNRegex.SubexpIndex("name")
		valueIdx := attributeValueFQNRegex.SubexpIndex("value")

		if len(valueMatches) <= namespaceIdx || len(valueMatches) <= nameIdx || len(valueMatches) <= valueIdx {
			return nil, fmt.Errorf("%w: valid attribute value FQN format https://<namespace>/attr/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
		}

		ns := strings.ToLower(valueMatches[namespaceIdx])
		name := strings.ToLower(valueMatches[nameIdx])
		value := strings.ToLower(valueMatches[valueIdx])

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

		ns := strings.ToLower(defMatches[namespaceIdx])
		name := strings.ToLower(defMatches[nameIdx])

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

		ns := strings.ToLower(nsMatches[namespaceIdx])
		isValid := validNamespaceRegex.MatchString(ns)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s", ErrInvalidFQNFormat, ns)
		}

		parsed.Namespace = ns
		return parsed, nil
	}

	return nil, errors.New("error: invalid attribute FQN format, must be https://<namespace>, https://<namespace>/attr/<name>, or https://<namespace>/attr/<name>/value/<value>")
}
