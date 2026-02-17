package sdk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

const (
	// maxListAttributesPages caps the pagination loop in ListAttributes to prevent
	// unbounded memory growth if a server repeatedly returns a non-zero next_offset.
	maxListAttributesPages = 1000

	// maxValidateFQNs matches the server-side limit on GetAttributeValuesByFqns
	// so callers get a clear local error instead of a cryptic server rejection.
	maxValidateFQNs = 250
)

// ListAttributes returns all active attributes available on the platform, auto-paginating
// through all results. An optional namespace name or ID may be provided to filter results.
//
// Use this before calling CreateTDF() to see what attributes are available for data tagging.
//
// Example:
//
//	attrs, err := sdk.ListAttributes(ctx)
//	for _, a := range attrs {
//	    fmt.Println(a.GetFqn())
//	}
func (s SDK) ListAttributes(ctx context.Context, namespace ...string) ([]*policy.Attribute, error) {
	req := &attributes.ListAttributesRequest{}
	if len(namespace) > 0 {
		req.Namespace = namespace[0]
	}

	var result []*policy.Attribute
	for pages := 0; pages < maxListAttributesPages; pages++ {
		resp, err := s.Attributes.ListAttributes(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("listing attributes: %w", err)
		}
		result = append(result, resp.GetAttributes()...)

		nextOffset := resp.GetPagination().GetNextOffset()
		if nextOffset == 0 {
			return result, nil
		}
		req.Pagination = &policy.PageRequest{Offset: nextOffset}
	}
	return nil, fmt.Errorf("listing attributes: exceeded maximum page limit (%d)", maxListAttributesPages)
}

// ValidateAttributes checks that all provided attribute value FQNs exist on the platform.
// This provides fail-fast behavior: validate attributes before calling CreateTDF() to avoid
// late-stage decryption failures caused by missing or misspelled attributes.
//
// fqns should be full attribute value FQNs in the form:
//
//	https://<namespace>/attr/<attribute_name>/value/<value>
//
// Returns ErrAttributeNotFound if any FQNs are missing, with the missing FQNs listed in
// the error message.
//
// Example:
//
//	err := sdk.ValidateAttributes(ctx, []string{
//	    "https://example.com/attr/classification/value/secret",
//	    "https://example.com/attr/clearance/value/top-secret",
//	})
//	if err != nil {
//	    log.Fatalf("attributes not found: %v", err)
//	}
func (s SDK) ValidateAttributes(ctx context.Context, fqns []string) error {
	if len(fqns) == 0 {
		return nil
	}

	if len(fqns) > maxValidateFQNs {
		return fmt.Errorf("too many attribute FQNs: %d exceeds maximum of %d", len(fqns), maxValidateFQNs)
	}

	for _, fqn := range fqns {
		if _, err := NewAttributeValueFQN(fqn); err != nil {
			return fmt.Errorf("invalid attribute value FQN %q: %w", fqn, err)
		}
	}

	resp, err := s.Attributes.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
	})
	if err != nil {
		return fmt.Errorf("validating attributes: %w", err)
	}

	found := resp.GetFqnAttributeValues()
	var missing []string
	for _, fqn := range fqns {
		if _, ok := found[fqn]; !ok {
			missing = append(missing, fqn)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrAttributeNotFound, strings.Join(missing, ", "))
	}
	return nil
}

// GetEntityAttributes returns the attribute value FQNs assigned to an entity (PE or NPE).
// Use this to inspect what attributes a user, service account, or other entity has been
// granted before making authorization decisions or constructing access policies.
//
// The entity parameter identifies the subject. Use the appropriate field for the entity type:
//
//	// By email address
//	entity := &authorization.Entity{Id: "e1", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "user@example.com"}}
//
//	// By username
//	entity := &authorization.Entity{Id: "e1", EntityType: &authorization.Entity_UserName{UserName: "alice"}}
//
//	// By client ID (NPE / service account)
//	entity := &authorization.Entity{Id: "e1", EntityType: &authorization.Entity_ClientId{ClientId: "my-service"}}
//
//	// By UUID
//	entity := &authorization.Entity{Id: "e1", EntityType: &authorization.Entity_Uuid{Uuid: "550e8400-e29b-41d4-a716-446655440000"}}
//
// Returns a slice of attribute value FQNs (e.g., "https://example.com/attr/clearance/value/secret").
func (s SDK) GetEntityAttributes(ctx context.Context, entity *authorization.Entity) ([]string, error) {
	if entity == nil {
		return nil, errors.New("entity must not be nil")
	}

	resp, err := s.Authorization.GetEntitlements(ctx, &authorization.GetEntitlementsRequest{
		Entities: []*authorization.Entity{entity},
	})
	if err != nil {
		return nil, fmt.Errorf("getting entity attributes: %w", err)
	}

	entityID := entity.GetId()
	for _, e := range resp.GetEntitlements() {
		if entityID == "" || e.GetEntityId() == entityID {
			return e.GetAttributeValueFqns(), nil
		}
	}
	return []string{}, nil
}

// ValidateAttributeValue checks that a single attribute value FQN is valid in format
// and exists on the platform.
//
// fqn should be a full attribute value FQN in the form:
//
//	https://<namespace>/attr/<attribute_name>/value/<value>
//
// This is a convenience wrapper around ValidateAttributes for the single-FQN case.
func (s SDK) ValidateAttributeValue(ctx context.Context, fqn string) error {
	return s.ValidateAttributes(ctx, []string{fqn})
}
