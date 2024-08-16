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
	`^https:\/\/(?<namespace>\S+)\/resm\/(?<name>\S+)$`,
)

// todo: logic could be made more generic in the future to support multiple FQN formats
// e.g. parse FQN for '/attr', '/value', '/resm' or some other method
func ParseResourceMappingGroupFqn(fqn string) (*FullyQualifiedResourceMappingGroup, error) {
	matches := resourceMappingGroupFqnRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	namespaceNameIdx := resourceMappingGroupFqnRegex.SubexpIndex("namespace")
	groupNameIdx := resourceMappingGroupFqnRegex.SubexpIndex("name")

	if numMatches < namespaceNameIdx || numMatches < groupNameIdx {
		return nil, errors.New("error: valid FQN format of https://<namespace>/resm/<group name> must be provided")
	}

	return &FullyQualifiedResourceMappingGroup{
		Fqn:       fqn,
		Namespace: matches[namespaceNameIdx],
		GroupName: matches[groupNameIdx],
	}, nil
}
