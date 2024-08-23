package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
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
		slog.InfoContext(ctx, ">>>>> upserted VALUE FQN",
			slog.String("fqn", fqn),
			slog.Any("error", err),
		)
	case opts.attributeID != "":
		fqn, err = c.Queries.UpsertAttributeDefinitionFqn(ctx, opts.attributeID)
		slog.InfoContext(ctx, ">>>>> upserting DEFINITION FQN",
			slog.String("fqn", fqn),
			slog.Any("error", err),
		)
	case opts.namespaceID != "":
		fqn, err = c.Queries.UpsertAttributeNamespaceFqn(ctx, opts.namespaceID)
		slog.InfoContext(ctx, ">>>>> upserting NAMESPACE FQN",
			slog.String("fqn", fqn),
			slog.Any("error", err),
		)
	default:
		err = fmt.Errorf("at least one of namespaceId, attributeId, or valueId must be set")
	}

	if err != nil {
		wrappedErr := db.WrapIfKnownInvalidQueryErr(err)
		c.logger.ErrorContext(ctx, "could not update FQN", slog.Any("opts", opts), slog.String("error", wrappedErr.Error()))
		return ""
	}

	// todo: change to Debug after testing
	c.logger.InfoContext(ctx, ">>>>>>> updated FQN", slog.String("fqn", fqn), slog.Any("opts", opts))
	return fqn
}

// AttrFqnReindex will reindex all namespace, attribute, and attribute_value FQNs
func (c *PolicyDBClient) AttrFqnReindex() (res struct { //nolint:nonamedreturns // Used to initialize an anonymous struct
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
	ns, err := c.ListNamespaces(context.Background(), StateAny)
	if err != nil {
		panic(fmt.Errorf("could not get namespaces: %w", err))
	}

	// Get all attributes
	attrs, err := c.ListAllAttributesWithout(context.Background(), StateAny)
	if err != nil {
		panic(fmt.Errorf("could not get attributes: %w", err))
	}

	// Get all attribute values
	values, err := c.ListAllAttributeValues(context.Background(), StateAny)
	if err != nil {
		panic(fmt.Errorf("could not get attribute values: %w", err))
	}

	// Reindex all namespaces
	for _, n := range ns {
		res.Namespaces = append(res.Namespaces, struct {
			ID  string
			Fqn string
		}{ID: n.GetId(), Fqn: c.upsertAttrFqn(context.Background(), attrFqnUpsertOptions{namespaceID: n.GetId()})})
	}

	// Reindex all attributes
	for _, a := range attrs {
		res.Attributes = append(res.Attributes, struct {
			ID  string
			Fqn string
		}{ID: a.GetId(), Fqn: c.upsertAttrFqn(context.Background(), attrFqnUpsertOptions{attributeID: a.GetId()})})
	}

	// Reindex all attribute values
	for _, av := range values {
		res.Values = append(res.Values, struct {
			ID  string
			Fqn string
		}{ID: av.GetId(), Fqn: c.upsertAttrFqn(context.Background(), attrFqnUpsertOptions{valueID: av.GetId()})})
	}

	return res
}

func (c *PolicyDBClient) GetAttributesByValueFqns(ctx context.Context, r *attributes.GetAttributeValuesByFqnsRequest) (map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, error) {
	if r.Fqns == nil || r.GetWithValue() == nil {
		return nil, errors.Join(db.ErrMissingValue, errors.New("error: one or more FQNs and a WithValue selector must be provided"))
	}
	list := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, len(r.GetFqns()))
	for _, fqn := range r.GetFqns() {
		// normalize to lower case
		fqn = strings.ToLower(fqn)
		// ensure the FQN corresponds to an attribute value and not a definition or namespace alone
		if !strings.Contains(fqn, "/value/") {
			return nil, db.ErrFqnMissingValue
		}
		attr, err := c.GetAttributeByFqn(ctx, fqn)
		if err != nil {
			c.logger.Error("could not get attribute by FQN", slog.String("fqn", fqn), slog.String("error", err.Error()))
			return nil, err
		}
		pair := &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Attribute: attr,
		}
		for _, v := range attr.GetValues() {
			if v.GetFqn() == fqn {
				pair.Value = v
			}
		}
		if pair.GetValue() == nil {
			c.logger.Error("could not find value for FQN", slog.String("fqn", fqn))
			return nil, fmt.Errorf("could not find value for FQN [%s] %w", fqn, db.ErrNotFound)
		}
		list[fqn] = pair
	}
	return list, nil
}
