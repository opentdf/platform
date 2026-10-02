package namespacedpolicy

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/otdfctl/migrations"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	actionKind              = "action"
	subjectConditionSetKind = "subject condition set"
	subjectMappingKind      = "subject mapping"
	registeredResourceKind  = "registered resource"
	obligationTriggerKind   = "obligation trigger"
)

func actionLabel(action *policy.Action) string {
	if action == nil {
		return unknownLabel
	}
	if name := strings.TrimSpace(action.GetName()); name != "" {
		return name
	}
	if id := strings.TrimSpace(action.GetId()); id != "" {
		return id
	}
	return unknownLabel
}

func plainPolicyActionNamesSummary(actions []*policy.Action) string {
	names := make([]string, 0, len(actions))
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if action == nil {
			continue
		}
		name := actionLabel(action)
		if strings.TrimSpace(name) == "" || name == unknownLabel {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, strconvQuote(name))
	}
	return plainListSummary(names)
}

func styledPolicyActionNamesSummary(styles *migrations.DisplayStyles, actions []*policy.Action) string {
	names := make([]string, 0, len(actions))
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if action == nil {
			continue
		}
		name := actionLabel(action)
		if strings.TrimSpace(name) == "" || name == unknownLabel {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, styles.Name().Render(strconvQuote(name)))
	}
	return strings.Join(names, ", ")
}

func plainRegisteredResourceSourceSummary(resource *policy.RegisteredResource) string {
	return appendDetails(
		"values="+plainRegisteredResourceValuesSummary(resource),
		"action_bindings="+plainRegisteredResourceActionAttributeValuesSummary(resource),
	)
}

func styledRegisteredResourceSourceSummary(styles *migrations.DisplayStyles, resource *policy.RegisteredResource) string {
	return appendDetails(
		"values="+styledRegisteredResourceValuesSummary(styles, resource),
		"action_bindings="+styledRegisteredResourceActionAttributeValuesSummary(styles, resource),
	)
}

func appendDetails(line string, details ...string) string {
	filtered := make([]string, 0, len(details))
	for _, detail := range details {
		if strings.TrimSpace(detail) != "" {
			filtered = append(filtered, detail)
		}
	}
	if len(filtered) == 0 {
		return line
	}
	return fmt.Sprintf("%s (%s)", line, strings.Join(filtered, ", "))
}

func strconvQuote(value string) string {
	return fmt.Sprintf("%q", value)
}

func valueFQN(value *policy.Value) string {
	if value == nil {
		return ""
	}
	if value.GetFqn() != "" {
		return value.GetFqn()
	}
	return value.GetId()
}

func plainRegisteredResourceValuesSummary(resource *policy.RegisteredResource) string {
	values := make([]string, 0, len(resource.GetValues()))
	seen := make(map[string]struct{}, len(resource.GetValues()))
	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}
		label := strings.TrimSpace(value.GetValue())
		if label == "" {
			label = strings.TrimSpace(value.GetId())
		}
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		values = append(values, strconvQuote(label))
	}
	return plainListSummary(values)
}

func styledRegisteredResourceValuesSummary(styles *migrations.DisplayStyles, resource *policy.RegisteredResource) string {
	values := make([]string, 0, len(resource.GetValues()))
	seen := make(map[string]struct{}, len(resource.GetValues()))
	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}
		label := strings.TrimSpace(value.GetValue())
		if label == "" {
			label = strings.TrimSpace(value.GetId())
		}
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		values = append(values, styles.Name().Render(strconvQuote(label)))
	}
	return strings.Join(values, ", ")
}

func plainRegisteredResourceActionAttributeValuesSummary(resource *policy.RegisteredResource) string {
	bindings := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}
		for _, binding := range value.GetActionAttributeValues() {
			if binding == nil {
				continue
			}
			label := fmt.Sprintf("%s -> %s", strconvQuote(actionLabel(binding.GetAction())), valueFQN(binding.GetAttributeValue()))
			if _, ok := seen[label]; ok {
				continue
			}
			seen[label] = struct{}{}
			bindings = append(bindings, label)
		}
	}
	return plainListSummary(bindings)
}

func styledRegisteredResourceActionAttributeValuesSummary(styles *migrations.DisplayStyles, resource *policy.RegisteredResource) string {
	bindings := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range resource.GetValues() {
		if value == nil {
			continue
		}
		for _, binding := range value.GetActionAttributeValues() {
			if binding == nil {
				continue
			}
			label := fmt.Sprintf(
				"%s -> %s",
				styles.Name().Render(strconvQuote(actionLabel(binding.GetAction()))),
				styles.Namespace().Render(valueFQN(binding.GetAttributeValue())),
			)
			if _, ok := seen[label]; ok {
				continue
			}
			seen[label] = struct{}{}
			bindings = append(bindings, label)
		}
	}
	return strings.Join(bindings, ", ")
}

func obligationLabel(obligation *policy.Obligation) string {
	if obligation == nil {
		return noneLabel
	}
	if fqn := strings.TrimSpace(obligation.GetFqn()); fqn != "" {
		return fqn
	}
	if name := strings.TrimSpace(obligation.GetName()); name != "" {
		return name
	}
	if id := strings.TrimSpace(obligation.GetId()); id != "" {
		return id
	}
	return noneLabel
}

func plainRequestContextsSummary(contexts []*policy.RequestContext) string {
	clientIDs := make([]string, 0, len(contexts))
	seen := make(map[string]struct{}, len(contexts))
	for _, requestContext := range contexts {
		clientID := strings.TrimSpace(requestContext.GetPep().GetClientId())
		if clientID == "" {
			continue
		}
		if _, ok := seen[clientID]; ok {
			continue
		}
		seen[clientID] = struct{}{}
		clientIDs = append(clientIDs, "client_id: "+strconvQuote(clientID))
	}
	return plainListSummary(clientIDs)
}

func plainListSummary(items []string) string {
	if len(items) == 0 {
		return noneLabel
	}
	return strings.Join(items, ", ")
}
