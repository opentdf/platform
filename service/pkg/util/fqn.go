package util

import (
	"errors"
	"regexp"
)

type FullyQualifiedResourceMappingGroup struct {
	Fqn       string
	Namespace string
	GroupName string
}

// protovalidate already validates the FQN format in the service request
// for parsing purposes, we can just look for any non-whitespace characters
// e.g. should be in format of "https://<namespace>/resm/<group name>"
var resourceMappingGroupFqnRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>\S+)\/resm\/(?<groupName>\S+)$`,
)

// todo: logic could be made more generic in the future to support multiple FQN formats
// e.g. parse FQN for '/attr', '/value', '/resm' or some other method
func ParseResourceMappingGroupFqn(fqn string) (*FullyQualifiedResourceMappingGroup, error) {
	matches := resourceMappingGroupFqnRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	namespaceIdx := resourceMappingGroupFqnRegex.SubexpIndex("namespace")
	groupNameIdx := resourceMappingGroupFqnRegex.SubexpIndex("groupName")

	if numMatches < namespaceIdx || numMatches < groupNameIdx {
		return nil, errors.New("error: valid FQN format of https://<namespace>/resm/<group name> must be provided")
	}

	return &FullyQualifiedResourceMappingGroup{
		Fqn:       fqn,
		Namespace: matches[namespaceIdx],
		GroupName: matches[groupNameIdx],
	}, nil
}

// Structs and regexes for attribute FQNs
type FullyQualifiedAttribute struct {
	Fqn       string
	Namespace string
	Name      string
	Value     string
}

// Regex for attribute value FQN format: https://<namespace>/attr/<n>/value/<value>
// The $ at the end ensures no extra segments after value
var attributeValueFQNRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>[^\/]+)\/attr\/(?<n>[^\/]+)\/value\/(?<value>[^\/]+)$`,
)

// Regex for attribute definition FQN format: https://<namespace>/attr/<n>
// The $ at the end ensures no extra segments after name
var attributeDefinitionFQNRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>[^\/]+)\/attr\/(?<n>[^\/]+)$`,
)

// Regex for just namespace: https://<namespace>
// Only match exactly https:// followed by a namespace with no forward slashes
var namespaceOnlyRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>[^\/]+)$`,
)

// ParseAttributeFqn parses an attribute FQN string into a FullyQualifiedAttribute struct.
// The FQN can be:
// - a namespace only FQN (https://<namespace>)
// - a definition FQN (https://<namespace>/attr/<n>)
// - a value FQN (https://<namespace>/attr/<n>/value/<value>)
func ParseAttributeFqn(fqn string) (*FullyQualifiedAttribute, error) {
	// First try to match against the attribute value pattern
	valueMatches := attributeValueFQNRegex.FindStringSubmatch(fqn)
	if len(valueMatches) > 0 {
		namespaceIdx := attributeValueFQNRegex.SubexpIndex("namespace")
		nameIdx := attributeValueFQNRegex.SubexpIndex("n")
		valueIdx := attributeValueFQNRegex.SubexpIndex("value")

		if len(valueMatches) <= namespaceIdx || len(valueMatches) <= nameIdx || len(valueMatches) <= valueIdx {
			return nil, errors.New("error: valid attribute value FQN format https://<namespace>/attr/<n>/value/<value> must be provided")
		}

		// Ensure the value isn't empty
		if valueMatches[valueIdx] == "" {
			return nil, errors.New("error: attribute value cannot be empty in FQN")
		}

		return &FullyQualifiedAttribute{
			Fqn:       fqn,
			Namespace: valueMatches[namespaceIdx],
			Name:      valueMatches[nameIdx],
			Value:     valueMatches[valueIdx],
		}, nil
	}

	// If not a value FQN, try to match against the attribute definition pattern
	defMatches := attributeDefinitionFQNRegex.FindStringSubmatch(fqn)
	if len(defMatches) > 0 {
		namespaceIdx := attributeDefinitionFQNRegex.SubexpIndex("namespace")
		nameIdx := attributeDefinitionFQNRegex.SubexpIndex("n")

		if len(defMatches) <= namespaceIdx || len(defMatches) <= nameIdx {
			return nil, errors.New("error: valid attribute definition FQN format https://<namespace>/attr/<n> must be provided")
		}

		// Ensure the name isn't empty
		if defMatches[nameIdx] == "" {
			return nil, errors.New("error: attribute name cannot be empty in FQN")
		}

		return &FullyQualifiedAttribute{
			Fqn:       fqn,
			Namespace: defMatches[namespaceIdx],
			Name:      defMatches[nameIdx],
			Value:     "",
		}, nil
	}

	// If not a definition FQN, try to match against just the namespace
	nsMatches := namespaceOnlyRegex.FindStringSubmatch(fqn)
	if len(nsMatches) > 0 {
		namespaceIdx := namespaceOnlyRegex.SubexpIndex("namespace")

		if len(nsMatches) <= namespaceIdx {
			return nil, errors.New("error: valid namespace FQN format https://<namespace> must be provided")
		}

		// Ensure the namespace isn't empty
		if nsMatches[namespaceIdx] == "" {
			return nil, errors.New("error: namespace cannot be empty in FQN")
		}

		return &FullyQualifiedAttribute{
			Fqn:       fqn,
			Namespace: nsMatches[namespaceIdx],
			Name:      "",
			Value:     "",
		}, nil
	}

	return nil, errors.New("error: invalid attribute FQN format, must be https://<namespace>, https://<namespace>/attr/<n>, or https://<namespace>/attr/<n>/value/<value>")
}
