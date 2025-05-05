package identifier

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type FullyQualifiedResourceMappingGroup struct {
	Namespace string
	GroupName string
}

var (
	// protovalidate already validates the FQN format in the service request
	// for parsing purposes, we can just look for any non-whitespace characters
	// e.g. should be in format of "https://<namespace>/resm/<group name>"
	resourceMappingGroupFqnRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>\S+)\/resm\/(?<groupName>\S+)$`,
	)
)

// parseResourceMappingGroupFqn parses a resource mapping group FQN string into a FullyQualifiedResourceMappingGroup struct.
// The FQN must be in the format: https://<namespace>/resm/<group name>
func parseResourceMappingGroupFqn(fqn string) (*FullyQualifiedResourceMappingGroup, error) {
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
		Namespace: ns,
		GroupName: groupName,
	}, nil
}

// Implementing FullyQualified interface for FullyQualifiedResourceMappingGroup
func (rmg *FullyQualifiedResourceMappingGroup) FQN() string {
	builder := strings.Builder{}
	builder.WriteString("https://")
	builder.WriteString(rmg.Namespace)
	builder.WriteString("/resm/")
	builder.WriteString(rmg.GroupName)
	return strings.ToLower(builder.String())
}

func (rmg *FullyQualifiedResourceMappingGroup) Validate() error {
	if !validNamespaceRegex.MatchString(rmg.Namespace) {
		return fmt.Errorf("%w: invalid namespace format %s", ErrInvalidFQNFormat, rmg.Namespace)
	}
	if !validObjectNameRegex.MatchString(rmg.GroupName) {
		return fmt.Errorf("%w: invalid group name format %s", ErrInvalidFQNFormat, rmg.GroupName)
	}
	return nil
}
