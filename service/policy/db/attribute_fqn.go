package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/pkg/db"
)

// These values are optional, but at least one must be set. The other values will be derived from
// the set values.
type attrFqnUpsertOptions struct {
	namespaceID string
	attributeID string
	valueID     string
}

// This logic is a bit complex. What we are trying to achieve is to upsert the fqn based on the
// combination of namespaceId, attributeId, and valueId. However, instead of requiring all three
// we want to support partial attribute FQNs. This means that we need to support the following
// combinations:
// 1. namespaceId
// 2. namespaceId, attributeId
// 3. namespaceId, attributeId, valueId
//
// This is a side effect -- errors will be swallowed and the fqn will be returned as an empty string
func (c *PolicyDBClient) upsertAttrFqn(ctx context.Context, opts attrFqnUpsertOptions) string {
	var (
		fqn string
		err error
	)

	switch {
	case opts.valueID != "":
		fqn, err = c.Queries.UpsertAttributeValueFqn(ctx, opts.valueID)
	case opts.attributeID != "":
		fqn, err = c.Queries.UpsertAttributeDefinitionFqn(ctx, opts.attributeID)
	case opts.namespaceID != "":
		fqn, err = c.Queries.UpsertAttributeNamespaceFqn(ctx, opts.namespaceID)
	default:
		err = fmt.Errorf("at least one of namespaceId, attributeId, or valueId must be set")
	}

	if err != nil {
		wrappedErr := db.WrapIfKnownInvalidQueryErr(err)
		c.logger.ErrorContext(ctx, "could not update FQN", slog.Any("opts", opts), slog.String("error", wrappedErr.Error()))
		return ""
	}

	c.logger.DebugContext(ctx, "updated FQN", slog.String("fqn", fqn), slog.Any("opts", opts))
	return fqn
}

// AttrFqnReindex will reindex all namespace, attribute, and attribute_value FQNs
func (c *PolicyDBClient) AttrFqnReindex(ctx context.Context) (res struct { //nolint:nonamedreturns // Used to initialize an anonymous struct
	Namespaces []struct {
		ID  string
		Fqn string
	}
	Attributes []struct {
		ID  string
		Fqn string
	}
	Values []struct {
		ID  string
		Fqn string
	}
},
) {
	// Get all namespaces
	// TODO: iterate instead of using arbitrary limit/offset
	ns, err := c.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: math.MaxInt32,
		},
	})
	if err != nil {
		panic(fmt.Errorf("could not get namespaces: %w", err))
	}

	// Get all attributes
	attrs, err := c.ListAllAttributes(ctx)
	if err != nil {
		panic(fmt.Errorf("could not get attributes: %w", err))
	}

	// Get all attribute values
	values, err := c.ListAllAttributeValues(ctx)
	if err != nil {
		panic(fmt.Errorf("could not get attribute values: %w", err))
	}

	// Reindex all namespaces
	for _, n := range ns {
		res.Namespaces = append(res.Namespaces, struct {
			ID  string
			Fqn string
		}{ID: n.GetId(), Fqn: c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: n.GetId()})})
	}

	// Reindex all attributes
	for _, a := range attrs {
		res.Attributes = append(res.Attributes, struct {
			ID  string
			Fqn string
		}{ID: a.GetId(), Fqn: c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeID: a.GetId()})})
	}

	// Reindex all attribute values
	for _, av := range values {
		res.Values = append(res.Values, struct {
			ID  string
			Fqn string
		}{ID: av.GetId(), Fqn: c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueID: av.GetId()})})
	}

	return res
}

func (c *PolicyDBClient) GetAttributesByValueFqns(ctx context.Context, r *attributes.GetAttributeValuesByFqnsRequest) (map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	fqns := r.GetFqns()

	// todo: move to proto validation
	if fqns == nil || r.GetWithValue() == nil {
		return nil, errors.Join(db.ErrMissingValue, errors.New("error: one or more FQNs and a WithValue selector must be provided"))
	}

	list := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, len(fqns))

	for i, fqn := range fqns {
		// normalize to lower case
		fqn = strings.ToLower(fqn)

		// ensure the FQN corresponds to an attribute value and not a definition or namespace alone
		// todo: move to proto validation
		if !strings.Contains(fqn, "/value/") {
			return nil, db.ErrFqnMissingValue
		}

		// update array with normalized FQN
		fqns[i] = fqn

		// prepopulate response map for easy lookup
		list[fqn] = nil
	}

	// get all attribute values by FQN
	attrs, err := c.ListAttributesByFqns(ctx, fqns)
	if err != nil {
		return nil, err
	}

	// loop through attributes to find values that match the requested FQNs
	for _, attr := range attrs {
		for _, val := range attr.GetValues() {
			valFqn := val.GetFqn()
			if _, ok := list[valFqn]; ok {
				// update response map with attribute and value pair if value FQN found
				list[valFqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
					Attribute: attr,
					Value:     val,
				}
			}
		}
	}

	// check if all requested FQNs were found
	for fqn, pair := range list {
		if pair == nil {
			return nil, fmt.Errorf("could not find value for FQN [%s]: %w", fqn, db.ErrNotFound)
		}
	}

	return list, nil
}
