package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"slices"
	"strings"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	policy "github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	policyStore "github.com/opentdf/platform/service/pkg/access/store"
	subjectmappingresolution "github.com/opentdf/platform/service/pkg/access/subject-mapping-resolution"
)

// Map of resources to ACL (mock database)
var mockACL = map[string][]string{
	"https://reg_res/granular/value/123": {"test@example.com", "test2@example.com"},
	"https://reg_res/granular/value/456": {"someone@gmail.com"},
}
var allowedGranularActions = []string{"read", "send"}

const (
	fieldEmailAddress     = "email"
	granularPluginPDPName = "granular-plugin-pdp"
)

type GranularCustomPdp struct {
	l                   *logger.Logger
	resourceFQNPrefixes []string
}

// Initializes a new GranularPDP
func (p *GranularCustomPdp) New(ctx context.Context, l *logger.Logger, _ policyStore.EntitlementPolicyStore, attributeFQNPrefixes []string) error {
	p.resourceFQNPrefixes = attributeFQNPrefixes
	p.l = l.With("component", granularPluginPDPName)
	return nil
}

func (p *GranularCustomPdp) Name() string {
	return granularPluginPDPName
}

// Granular plugin PDP is always ready
func (p *GranularCustomPdp) IsReady(_ context.Context) bool {
	return true
}

// Ensure the decision is one of the allowed decision and a valid resource, then check
// the email in the entity representation against our in-memory ACL
func (p *GranularCustomPdp) GetDecision(
	ctx context.Context,
	entityRepresentation *ersV2.EntityRepresentation,
	_ *subjectmappingresolution.AttributeValueFQNsToActions,
	action *policy.Action,
	resource *authzV2.Resource,
) (bool, error) {
	if !p.IsValidDecisionableResource(resource) {
		return false, errors.New("resource is not decisionable")
	}
	if !p.IsValidDecisionableAction(action) {
		return false, errors.New("action is not decisionable")
	}

	var entityEmail string
	for _, prop := range entityRepresentation.GetAdditionalProps() {
		for field, value := range prop.GetFields() {
			if field == fieldEmailAddress {
				if e, err := mail.ParseAddress(value.GetStringValue()); err == nil {
					entityEmail = e.Address
					break
				}
			}
		}
		if entityEmail != "" {
			break
		}
	}

	if entityEmail == "" {
		return false, fmt.Errorf("no email found in entity representation")
	}

	granularResourceFQN := resource.GetRegisteredResourceValueFqn()
	for resourceName, acl := range mockACL {
		if resourceName == granularResourceFQN {
			if slices.Contains(acl, entityEmail) {
				return true, nil
			}
			p.l.DebugContext(ctx, "access denied per the ACL", slog.String("email", entityEmail), slog.String("resource", resourceName))
			return false, errors.New("access denied")
		}
	}

	return false, nil
}

// Ensures resource is a registered resource with an FQN matching configured prefix
func (p *GranularCustomPdp) IsValidDecisionableResource(resource *authzV2.Resource) bool {
	switch resource.GetResource().(type) {
	case *authzV2.Resource_RegisteredResourceValueFqn:
		for _, prefix := range p.resourceFQNPrefixes {
			if strings.HasPrefix(resource.GetRegisteredResourceValueFqn(), prefix) {
				return true
			}
		}
	}
	return false
}

// Check our allowed actions
func (p *GranularCustomPdp) IsValidDecisionableAction(action *policy.Action) bool {
	return slices.Contains(allowedGranularActions, strings.ToLower(action.GetName()))
}
