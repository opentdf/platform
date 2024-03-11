package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Masterminds/squirrel"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

// These values are optional, but at least one must be set. The other values will be derived from
// the set values.
type attrFqnUpsertOptions struct {
	namespaceId string
	attributeId string
	valueId     string
}

// This logic is a bit complex. What we are trying to achieve is to upsert the fqn based on the
// combination of namespaceId, attributeId, and valueId. However, instead of requiring all three
// we want to support partial attribute FQNs. This means that we need to support the following
// combinations:
// 1. namespaceId
// 2. namespaceId, attributeId
// 3. namespaceId, attributeId, valueId
func upsertAttrFqnSql(namespaceId string, attributeId string, valueId string) (string, []interface{}, error) {
	t := Tables.AttrFqn
	nT := Tables.Namespaces
	adT := Tables.Attributes
	avT := Tables.AttributeValues

	sb := db.NewStatementBuilder()
	var subQ squirrel.SelectBuilder
	// Since we are creating relationships we don't need to know the namespaceId when given the
	// valueId. This is because the valueId is unique across all namespaces.
	if valueId != "" {
		subQ = sb.Select("n.id", "ad.id", "av.id", "CONCAT('https://', n.name, '/attr/', ad.name, '/value/', av.value) AS fqn").
			From(nT.Name()+" n").
			Join(adT.Name()+" ad ON ad.namespace_id = n.id").
			Join(avT.Name()+" av ON av.attribute_definition_id = ad.id").
			Where("av.id = ?", valueId)
	} else if attributeId != "" {
		subQ = sb.Select("n.id", "ad.id", "NULL", "CONCAT('https://', n.name, '/attr/', ad.name) AS fqn").
			From(nT.Name()+" n").
			Join(adT.Name()+" ad ON ad.namespace_id = n.id").
			Where("ad.id = ?", attributeId)
	} else if namespaceId != "" {
		subQ = sb.Select("n.id", "NULL", "NULL", "CONCAT('https://', n.name) AS fqn").
			From(nT.Name()+" n").
			Where("n.id = ?", namespaceId)
	} else {
		return "", nil, fmt.Errorf("at least one of namespaceId, attributeId, or valueId must be set")
	}

	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("namespace_id", "attribute_id", "value_id", "fqn").
		Select(subQ).
		Suffix("ON CONFLICT (namespace_id, attribute_id, value_id) DO UPDATE SET fqn = EXCLUDED.fqn" +
			" RETURNING fqn").
		ToSql()
}

// This is a side effect -- errors will be swallowed and the fqn will be returned as an empty string
func (c *PolicyDbClient) upsertAttrFqn(ctx context.Context, opts attrFqnUpsertOptions) string {
	sql, args, err := upsertAttrFqnSql(opts.namespaceId, opts.attributeId, opts.valueId)
	if err != nil {
		slog.Error("could not update FQN", slog.Any("opts", opts), slog.String("error", err.Error()))
		return ""
	}

	r, err := c.QueryRow(ctx, sql, args, nil)
	if err != nil {
		slog.Error("could not update FQN", slog.Any("opts", opts), slog.String("error", err.Error()))
		return ""
	}

	var fqn string
	if err := r.Scan(&fqn); err != nil {
		slog.Error("could not update FQN", slog.Any("opts", opts), slog.String("error", err.Error()))
		return ""
	}

	slog.Debug("updated FQN", slog.String("fqn", fqn), slog.Any("opts", opts))
	return fqn
}

// AttrFqnReindex will reindex all namespace, attribute, and attribute_value FQNs
func (c *PolicyDbClient) AttrFqnReindex() (res struct {
	Namespaces []struct {
		Id  string
		Fqn string
	}
	Attributes []struct {
		Id  string
		Fqn string
	}
	Values []struct {
		Id  string
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
			Id  string
			Fqn string
		}{Id: n.Id, Fqn: c.upsertAttrFqn(context.Background(), attrFqnUpsertOptions{namespaceId: n.Id})})
	}

	// Reindex all attributes
	for _, a := range attrs {
		res.Attributes = append(res.Attributes, struct {
			Id  string
			Fqn string
		}{Id: a.Id, Fqn: c.upsertAttrFqn(context.Background(), attrFqnUpsertOptions{attributeId: a.Id})})
	}

	// Reindex all attribute values
	for _, av := range values {
		res.Values = append(res.Values, struct {
			Id  string
			Fqn string
		}{Id: av.Id, Fqn: c.upsertAttrFqn(context.Background(), attrFqnUpsertOptions{valueId: av.Id})})
	}

	return res
}

func filterValues(values []*attributes.Value, fqn string) *attributes.Value {
	val := strings.Split(fqn, "/value/")[1]
	for _, v := range values {
		if v.Value == val {
			return v
		}
	}
	return nil
}

func (c *PolicyDbClient) GetAttributesByValueFqns(ctx context.Context, fqns []string) (map[string]*attributes.AttributeAndValue, error) {
	list := make(map[string]*attributes.AttributeAndValue, len(fqns))
	for _, fqn := range fqns {
		// ensure the FQN corresponds to an attribute value and not a definition or namespace alone
		if !strings.Contains(fqn, "/value/") {
			return nil, db.ErrFqnMissingValue
		}
		attr, err := c.GetAttributeByFqn(ctx, fqn)
		if err != nil {
			slog.Error("could not get attribute by FQN", slog.String("fqn", fqn), slog.String("error", err.Error()))
			return nil, err
		}
		selected := filterValues(attr.Values, fqn)
		if selected == nil {
			slog.Error("could not find value for FQN", slog.String("fqn", fqn))
			return nil, fmt.Errorf("could not find value for FQN: %s", fqn)
		}
		list[fqn] = &attributes.AttributeAndValue{
			Attribute: attr,
			Value:     filterValues(attr.Values, fqn),
		}
	}
	return list, nil
}
