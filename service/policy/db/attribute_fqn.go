package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/pkg/db"
)

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
	ns, err := c.ListNamespaces(ctx, StateAny)
	if err != nil {
		panic(fmt.Errorf("could not get namespaces: %w", err))
	}

	// Reindex all namespaces
	reindexedRecords := []UpsertAttributeNamespaceFqnRow{}
	for _, n := range ns {
		rows, err := c.Queries.UpsertAttributeNamespaceFqn(ctx, n.GetId())
		if err != nil {
			panic(fmt.Errorf("could not update namespace [%s] FQN: %w", n.GetId(), err))
		}
		reindexedRecords = append(reindexedRecords, rows...)
	}

	for _, r := range reindexedRecords {
		switch {
		case r.AttributeID == "" && r.ValueID == "":
			// namespace record
			res.Namespaces = append(res.Namespaces, struct {
				ID  string
				Fqn string
			}{ID: r.NamespaceID, Fqn: r.Fqn})
		case r.ValueID == "":
			// attribute definition record
			res.Attributes = append(res.Attributes, struct {
				ID  string
				Fqn string
			}{ID: r.AttributeID, Fqn: r.Fqn})
		default:
			// attribute value record
			res.Values = append(res.Values, struct {
				ID  string
				Fqn string
			}{ID: r.ValueID, Fqn: r.Fqn})
		}
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
