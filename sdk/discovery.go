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
	if len(namespace) > 1 {
		return nil, fmt.Errorf("ListAttributes accepts at most one namespace filter, got %d", len(namespace))
	}
	req := &attributes.ListAttributesRequest{}
	if len(namespace) == 1 {
		req.Namespace = namespace[0]
	}

	var result []*policy.Attribute
	for pages := 0; pages < maxListAttributesPages; pages++ {
		resp, err := s.Attributes.ListAttributes(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("listing attributes: %w", err)
		}
		if pages == 0 {
			if total := resp.GetPagination().GetTotal(); total > 0 {
				result = make([]*policy.Attribute, 0, total)
			}
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
//	err := sdk.ValidateAttributes(ctx,
//	    "https://example.com/attr/classification/value/secret",
//	    "https://example.com/attr/clearance/value/top-secret",
//	)
//	if err != nil {
//	    log.Fatalf("attributes not found: %v", err)
//	}
func (s SDK) ValidateAttributes(ctx context.Context, fqns ...string) error {
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

	// GetEntitlements returns a slice of EntityEntitlements keyed by entity ID.
	// Even though we only request one entity, we must match by ID to locate the
	// correct entry — the response slice position is not guaranteed to correspond
	// to the request slice position.
	entityID := entity.GetId()
	for _, e := range resp.GetEntitlements() {
		if e.GetEntityId() == entityID {
			return e.GetAttributeValueFqns(), nil
		}
	}
	return nil, nil
}

// ValidateAttributeExists checks that a single attribute value FQN is valid in format
// and exists on the platform.
//
// fqn should be a full attribute value FQN in the form:
//
//	https://<namespace>/attr/<attribute_name>/value/<value>
//
// This is a convenience wrapper around ValidateAttributes for the single-FQN case.
func (s SDK) ValidateAttributeExists(ctx context.Context, fqn string) error {
	return s.ValidateAttributes(ctx, fqn)
}

// ValidateAttributeValue checks that value is a permitted value for the attribute identified
// by attributeFqn. This handles both enumerated and dynamic attribute types:
//   - Enumerated attributes: value must match one of the pre-registered values (case-insensitive).
//   - Dynamic attributes (no pre-registered values): any non-empty value is accepted.
//
// attributeFqn should be an attribute-level FQN in the form:
//
//	https://<namespace>/attr/<attribute_name>
//
// Returns ErrAttributeNotFound if the attribute does not exist, or if the attribute is
// enumerated and value is not in the allowed set.
//
// Example:
//
//	err := sdk.ValidateAttributeValue(ctx, "https://example.com/attr/clearance", "secret")
//	if err != nil {
//	    log.Fatalf("value not permitted: %v", err)
//	}
func (s SDK) ValidateAttributeValue(ctx context.Context, attributeFqn string, value string) error {
	if value == "" {
		return fmt.Errorf("invalid attribute value: must not be empty")
	}
	if _, err := NewAttributeNameFQN(attributeFqn); err != nil {
		return fmt.Errorf("invalid attribute FQN %q: %w", attributeFqn, err)
	}

	resp, err := s.Attributes.GetAttribute(ctx, &attributes.GetAttributeRequest{
		Identifier: &attributes.GetAttributeRequest_Fqn{Fqn: attributeFqn},
	})
	if err != nil {
		return fmt.Errorf("%w: %s", ErrAttributeNotFound, attributeFqn)
	}

	vals := resp.GetAttribute().GetValues()
	if len(vals) == 0 {
		// Dynamic attribute — any value is permitted.
		return nil
	}

	for _, v := range vals {
		if strings.EqualFold(v.GetValue(), value) {
			return nil
		}
	}
	return fmt.Errorf("%w: value %q not permitted for attribute %s", ErrAttributeNotFound, value, attributeFqn)
}
