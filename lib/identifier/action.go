package identifier

import (
	"fmt"
	"regexp"
	"strings"
)

const actionFQNSplitParts = 2

// Structs and regexes for action FQNs
type FullyQualifiedAction struct {
	Namespace string
	Name      string
}

// Regex for action definition FQN format: https://<namespace>/act/<name>
// The $ at the end ensures no extra segments after name
var actionDefinitionFQNRegex = regexp.MustCompile(
	`^https:\/\/(?<namespace>[^\/]+)\/act\/(?<name>[^\/]+)$`,
)

// Implementing FullyQualified interface for FullyQualifiedAction
func (act *FullyQualifiedAction) FQN() string {
	builder := strings.Builder{}
	builder.WriteString("https://")
	builder.WriteString(act.Namespace)

	// if name is present, append it to the FQN
	if act.Name != "" {
		builder.WriteString("/act/")
		builder.WriteString(act.Name)
	}
	return strings.ToLower(builder.String())
}

func (act *FullyQualifiedAction) Validate() error {
	if !validNamespaceRegex.MatchString(act.Namespace) {
		return fmt.Errorf("%w: invalid namespace format %s", ErrInvalidFQNFormat, act.Namespace)
	}

	// Only validate name if it is present
	if act.Name != "" && !validObjectNameRegex.MatchString(act.Name) {
		return fmt.Errorf("%w: invalid action name format %s", ErrInvalidFQNFormat, act.Name)
	}

	return nil
}

// parseActionFqn parses an action FQN string into a FullyQualifiedAction struct.
// The FQN can be:
// - a namespace only FQN (https://<namespace>)
// - an action FQN (https://<namespace>/act/<name>)
func parseActionFqn(fqn string) (*FullyQualifiedAction, error) {
	parsed := &FullyQualifiedAction{}

	// First try to match against the action definition pattern
	defMatches := actionDefinitionFQNRegex.FindStringSubmatch(fqn)
	if len(defMatches) > 0 {
		namespaceIdx := actionDefinitionFQNRegex.SubexpIndex("namespace")
		nameIdx := actionDefinitionFQNRegex.SubexpIndex("name")

		if len(defMatches) <= namespaceIdx || len(defMatches) <= nameIdx {
			return nil, fmt.Errorf("%w: valid action definition FQN format https://<namespace>/act/<name> must be provided [%s]", ErrInvalidFQNFormat, fqn)
		}

		ns := strings.ToLower(defMatches[namespaceIdx])
		name := strings.ToLower(defMatches[nameIdx])

		isValid := validNamespaceRegex.MatchString(ns) && validObjectNameRegex.MatchString(name)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s with action name %s", ErrInvalidFQNFormat, ns, name)
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
			return nil, fmt.Errorf("%w: valid namespace FQN format https://<namespace> must be provided [%s]", ErrInvalidFQNFormat, fqn)
		}

		ns := strings.ToLower(nsMatches[namespaceIdx])
		isValid := validNamespaceRegex.MatchString(ns)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s", ErrInvalidFQNFormat, ns)
		}

		parsed.Namespace = ns
		return parsed, nil
	}

	return nil, fmt.Errorf("%w, must be https://<namespace>, https://<namespace>/act/<name>", ErrInvalidFQNFormat)
}

func BreakActFQN(fqn string) (string, string) {
	parts := strings.SplitN(fqn, "/act/", actionFQNSplitParts)
	if len(parts) == actionFQNSplitParts {
		return parts[0], strings.ToLower(parts[1])
	}
	return fqn, ""
}

func BuildActFQN(nsFQN, actName string) string {
	return nsFQN + "/act/" + strings.ToLower(actName)
}
