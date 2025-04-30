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

type FullyQualifiedRegisteredResourceValue struct {
	Fqn   string
	Name  string
	Value string
}

// protovalidate already validates the FQN format in the service request
// for parsing purposes, we can just look for any non-whitespace characters
// e.g. should be in format of "https://<namespace>/resm/<group name>"
var resourceMappingGroupFqnRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>\S+)\/resm\/(?<name>\S+)$`,
)

var registeredResourceValueFqnRegex = regexp.MustCompile(
	`^https:\/\/reg_res\/(?<name>\S+)\/value\/(?<value>\S+)$`,
)

// todo: is it possible to make this more generic and support all fqn formats?

func ParseResourceMappingGroupFqn(fqn string) (*FullyQualifiedResourceMappingGroup, error) {
	matches := resourceMappingGroupFqnRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	namespaceIdx := resourceMappingGroupFqnRegex.SubexpIndex("namespace")
	groupNameIdx := resourceMappingGroupFqnRegex.SubexpIndex("name")

	if numMatches < namespaceIdx || numMatches < groupNameIdx {
		return nil, errors.New("error: valid FQN format of https://<namespace>/resm/<group name> must be provided")
	}

	return &FullyQualifiedResourceMappingGroup{
		Fqn:       fqn,
		Namespace: matches[namespaceIdx],
		GroupName: matches[groupNameIdx],
	}, nil
}

func ParseRegisteredResourceValueFqn(fqn string) (*FullyQualifiedRegisteredResourceValue, error) {
	matches := registeredResourceValueFqnRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	nameIdx := registeredResourceValueFqnRegex.SubexpIndex("name")
	valueIdx := registeredResourceValueFqnRegex.SubexpIndex("value")

	if numMatches < nameIdx || numMatches < valueIdx {
		return nil, errors.New("error: valid FQN format of https://reg_res/<name>/value/<value> must be provided")
	}

	return &FullyQualifiedRegisteredResourceValue{
		Fqn:   fqn,
		Name:  matches[nameIdx],
		Value: matches[valueIdx],
	}, nil
}
