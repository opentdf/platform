package util

import (
	"errors"
	"regexp"
)

type ResourceMappingGroupFQN struct {
	Namespace string
	GroupName string
}

// todo: patterns stored in variables for future extensibility
// - could expose the patterns if needed

// todo: temporary -> current namespace pattern in create proto validator is not correct (e.g. "example.com" fails validation, but is valid)
var namespacePattern = `\S+`

var attrNamePattern = `[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?`

var validFQNRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>` + namespacePattern + `)\/resm\/(?<name>` + attrNamePattern + `)$`,
)

// todo: logic could be made more generic in the future to support multiple FQN formats
// e.g. parse FQN for '/attr', '/value', '/resm' or some other method

func IsValidResourceMappingGroupFqn(fqn string) bool {
	return validFQNRegex.MatchString(fqn)
}

func ParseResourceMappingGroupFqn(fqn string) (*ResourceMappingGroupFQN, error) {
	matches := validFQNRegex.FindStringSubmatch(fqn)
	numMatches := len(matches)

	namespaceNameIdx := validFQNRegex.SubexpIndex("namespace")
	groupNameIdx := validFQNRegex.SubexpIndex("name")

	if numMatches < namespaceNameIdx || numMatches < groupNameIdx {
		return nil, errors.New("error: valid FQN format of https://<namespace>/resm/<unique_name> must be provided")
	}

	return &ResourceMappingGroupFQN{
		Namespace: matches[namespaceNameIdx],
		GroupName: matches[groupNameIdx],
	}, nil
}
