package identifier

import (
	"fmt"
	"regexp"
	"strings"
)

// Structs and regexes for obligation FQNs
type FullyQualifiedObligation struct {
	Namespace string
	Name      string
	Value     string
}

var (
	// Regex for obligation value FQN format: https://<namespace>/obl/<name>/value/<value>
	// The $ at the end ensures no extra segments after value
	obligationValueFQNRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>[^\/]+)\/obl\/(?<name>[^\/]+)\/value\/(?<value>[^\/]+)$`,
	)

	// Regex for obligation definition FQN format: https://<namespace>/obl/<name>
	// The $ at the end ensures no extra segments after name
	obligationDefinitionFQNRegex = regexp.MustCompile(
		`^https:\/\/(?<namespace>[^\/]+)\/obl\/(?<name>[^\/]+)$`,
	)
)

// Implementing FullyQualified interface for FullyQualifiedObligation
func (obl *FullyQualifiedObligation) FQN() string {
	builder := strings.Builder{}
	builder.WriteString("https://")
	builder.WriteString(obl.Namespace)

	// if name, must be valid
	if obl.Name != "" {
		builder.WriteString("/obl/")
		builder.WriteString(obl.Name)

		if obl.Value != "" {
			builder.WriteString("/value/")
			builder.WriteString(obl.Value)
		}
	}
	return strings.ToLower(builder.String())
}

func (obl *FullyQualifiedObligation) Validate() error {
	if !validNamespaceRegex.MatchString(obl.Namespace) {
		return fmt.Errorf("%w: invalid namespace format %s", ErrInvalidFQNFormat, obl.Namespace)
	}

	// Only validate name and value if they are present
	if obl.Name != "" && !validObjectNameRegex.MatchString(obl.Name) {
		return fmt.Errorf("%w: invalid obligation name format %s", ErrInvalidFQNFormat, obl.Name)
	}

	if obl.Value != "" && !validObjectNameRegex.MatchString(obl.Value) {
		return fmt.Errorf("%w: invalid obligation value format %s", ErrInvalidFQNFormat, obl.Value)
	}

	return nil
}

// parseObligationFqn parses an obligation FQN string into a FullyQualifiedObligation struct.
// The FQN can be:
// - a namespace only FQN (https://<namespace>)
// - a definition FQN (https://<namespace>/obl/<name>)
// - a value FQN (https://<namespace>/obl/<name>/value/<value>)
func parseObligationFqn(fqn string) (*FullyQualifiedObligation, error) {
	parsed := &FullyQualifiedObligation{}

	// First try to match against the obligation value pattern
	valueMatches := obligationValueFQNRegex.FindStringSubmatch(fqn)
	if len(valueMatches) > 0 {
		namespaceIdx := obligationValueFQNRegex.SubexpIndex("namespace")
		nameIdx := obligationValueFQNRegex.SubexpIndex("name")
		valueIdx := obligationValueFQNRegex.SubexpIndex("value")

		if len(valueMatches) <= namespaceIdx || len(valueMatches) <= nameIdx || len(valueMatches) <= valueIdx {
			return nil, fmt.Errorf("%w: valid obligation value FQN format https://<namespace>/obl/<name>/value/<value> must be provided", ErrInvalidFQNFormat)
		}

		ns := strings.ToLower(valueMatches[namespaceIdx])
		name := strings.ToLower(valueMatches[nameIdx])
		value := strings.ToLower(valueMatches[valueIdx])

		isValid := validNamespaceRegex.MatchString(ns) && validObjectNameRegex.MatchString(name) && validObjectNameRegex.MatchString(value)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s with obligation name %s and value %s", ErrInvalidFQNFormat, ns, name, value)
		}

		parsed.Namespace = ns
		parsed.Name = name
		parsed.Value = value

		return parsed, nil
	}

	// If not a value FQN, try to match against the obligation definition pattern
	defMatches := obligationDefinitionFQNRegex.FindStringSubmatch(fqn)
	if len(defMatches) > 0 {
		namespaceIdx := obligationDefinitionFQNRegex.SubexpIndex("namespace")
		nameIdx := obligationDefinitionFQNRegex.SubexpIndex("name")

		if len(defMatches) <= namespaceIdx || len(defMatches) <= nameIdx {
			return nil, fmt.Errorf("%w: valid obligation definition FQN format https://<namespace>/obl/<name> must be provided [%s]", ErrInvalidFQNFormat, fqn)
		}

		ns := strings.ToLower(defMatches[namespaceIdx])
		name := strings.ToLower(defMatches[nameIdx])

		isValid := validNamespaceRegex.MatchString(ns) && validObjectNameRegex.MatchString(name)
		if !isValid {
			return nil, fmt.Errorf("%w: found namespace %s with obligation name %s", ErrInvalidFQNFormat, ns, name)
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

	return nil, fmt.Errorf("%w, must be https://<namespace>, https://<namespace>/obl/<name>, or https://<namespace>/obl/<name>/value/<value>", ErrInvalidFQNFormat)
}

func BreakOblFQN(fqn string) (string, string) {
	nsFQN := strings.Split(fqn, "/obl/")[0]
	parts := strings.Split(fqn, "/")
	oblName := strings.ToLower(parts[len(parts)-1])
	return nsFQN, oblName
}

func BreakOblValFQN(fqn string) (string, string, string) {
	parts := strings.Split(fqn, "/value/")
	nsFQN, oblName := BreakOblFQN(parts[0])
	oblVal := strings.ToLower(parts[len(parts)-1])
	return nsFQN, oblName, oblVal
}

func BuildOblFQN(nsFQN, oblName string) string {
	return nsFQN + "/obl/" + strings.ToLower(oblName)
}

func BuildOblValFQN(nsFQN, oblName, oblVal string) string {
	return BuildOblFQN(nsFQN, oblName) + "/value/" + strings.ToLower(oblVal)
}
