package db

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	AttributeTable              = tableName(TableAttributes)
	AttributeRuleTypeEnumPrefix = "ATTRIBUTE_RULE_TYPE_ENUM_"
)

func attributesRuleTypeEnumTransformIn(value string) string {
	return strings.TrimPrefix(value, AttributeRuleTypeEnumPrefix)
}

func attributesRuleTypeEnumTransformOut(value string) attributes.AttributeRuleTypeEnum {
	return attributes.AttributeRuleTypeEnum(attributes.AttributeRuleTypeEnum_value[AttributeRuleTypeEnumPrefix+value])
}

func attributesValuesProtojson(valuesJson []byte, values []*attributes.Value) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(valuesJson, &raw); err != nil {
		return err
	}

	for _, r := range raw {
		value := attributes.Value{}
		if err := protojson.Unmarshal(r, &value); err != nil {
			return err
		}
		values = append(values, &value)
	}
	return nil
}

func attributesSelect() sq.SelectBuilder {
	return newStatementBuilder().Select(
		tableField(AttributeTable, "id"),
		tableField(AttributeTable, "name"),
		tableField(AttributeTable, "rule"),
		tableField(AttributeTable, "metadata"),
		"JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', "+tableField(AttributeValueTable, "id")+", "+
			"'value', "+tableField(AttributeValueTable, "value")+","+
			"'members', "+tableField(AttributeValueTable, "members")+
			")"+
			") AS values",
	).
		LeftJoin(AttributeValueTable + " ON " + AttributeValueTable + ".id = " + AttributeTable + ".id").
		GroupBy(tableField(AttributeTable, "id"))
}

func attributesHydrateItem(row pgx.Row) (*attributes.Attribute, error) {
	var (
		id           string
		name         string
		rule         string
		metadataJson []byte
		valuesJson   []byte
	)
	err := row.Scan(&id, &name, &rule, &metadataJson, &valuesJson)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, err
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	v := make([]*attributes.Value, 0)
	if valuesJson != nil {
		if err := attributesValuesProtojson(valuesJson, v); err != nil {
			return nil, err
		}
	}

	attr := &attributes.Attribute{
		Id:       id,
		Name:     name,
		Rule:     attributesRuleTypeEnumTransformOut(rule),
		Metadata: m,
		Values:   v,
	}

	return attr, nil
}

func attributesHydrateList(rows pgx.Rows) ([]*attributes.Attribute, error) {
	list := make([]*attributes.Attribute, 0)
	for rows.Next() {
		slog.Info("next")
		var (
			id           string
			name         string
			rule         string
			metadataJson []byte
			valuesJson   []byte
		)
		err := rows.Scan(&id, &name, &rule, &metadataJson, &valuesJson)
		if err != nil {
			return nil, err
		}

		attribute := &attributes.Attribute{
			Id:   id,
			Name: name,
			Rule: attributesRuleTypeEnumTransformOut(rule),
		}

		if metadataJson != nil {
			m := &common.Metadata{}
			if err := protojson.Unmarshal(metadataJson, m); err != nil {
				return nil, err
			}
			attribute.Metadata = m
		}

		if valuesJson != nil {
			v := make([]*attributes.Value, 0)
			if err := attributesValuesProtojson(valuesJson, v); err != nil {
				return nil, err
			}
			attribute.Values = v
		}

		list = append(list, attribute)
	}
	return list, nil
}

///
// CRUD operations
///

func listAllAttributesSql() (string, []interface{}, error) {
	return attributesSelect().
		From(AttributeTable).
		ToSql()
}
func (c Client) ListAllAttributes(ctx context.Context) ([]*attributes.Attribute, error) {
	sql, args, err := listAllAttributesSql()
	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}
	slog.Info("list", slog.Any("list", list))

	return list, nil
}

func getAttributeSql(id string) (string, []interface{}, error) {
	return attributesSelect().
		Where(sq.Eq{tableField(AttributeTable, "id"): id}).
		From(AttributeTable).
		ToSql()
}
func (c Client) GetAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	sql, args, err := getAttributeSql(id)
	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	attribute, err := attributesHydrateItem(row)
	if err != nil {
		slog.Error("could not hydrate item", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	return attribute, nil
}

func getAttributesByNamespaceSql(namespaceId string) (string, []interface{}, error) {
	return attributesSelect().
		Where(sq.Eq{tableField(AttributeTable, "namespace_id"): namespaceId}).
		From(AttributeTable).
		ToSql()
}
func (c Client) GetAttributesByNamespace(ctx context.Context, namespaceId string) ([]*attributes.Attribute, error) {
	sql, args, err := getAttributesByNamespaceSql(namespaceId)

	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	return list, nil
}

func createAttributeSql(namespaceId string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(AttributeTable).
		Columns("namespace_id", "name", "rule", "metadata").
		Values(namespaceId, name, rule, metadata).
		Suffix("RETURNING \"id\"").
		ToSql()
}
func (c Client) CreateAttribute(ctx context.Context, attr *attributes.AttributeCreateUpdate) (*attributes.Attribute, error) {
	metadataJson, metadata, err := marshalCreateMetadata(attr.Metadata)
	if err != nil {
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}

	sql, args, err := createAttributeSql(attr.NamespaceId, attr.Name, attributesRuleTypeEnumTransformIn(attr.Rule.String()), metadataJson)
	// TODO: abstract error checking to be DRY
	// TODO: check for constraint violation
	// - duplicate name
	// - namespace id exists
	var id string
	if r, err := c.queryRow(ctx, sql, args, err); err != nil {
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	} else if err := r.Scan(&id); err != nil {
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}

	a := &attributes.Attribute{
		Id:       id,
		Name:     attr.Name,
		Rule:     attr.Rule,
		Metadata: metadata,
	}
	return a, nil
}

func updateAttributeSql(id string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	sb := newStatementBuilder().
		Update(AttributeTable)

	if name != "" {
		sb = sb.Set("name", name)
	}
	if rule != "" {
		sb = sb.Set("rule", rule)
	}

	return sb.Set("metadata", metadata).
		Where(sq.Eq{tableField(AttributeTable, "id"): id}).
		ToSql()
}
func (c Client) UpdateAttribute(ctx context.Context, id string, attr *attributes.AttributeCreateUpdate) (*attributes.Attribute, error) {
	// get attribute before updating
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("scope", "getAttribute"), slog.String("error", err.Error()))
		return nil, status.Error(status.Code(err), services.ErrUpdatingResource)
	}

	metadataJson, _, err := marshalUpdateMetadata(a.Metadata, attr.Metadata)
	if err != nil {
		return nil, status.Error(codes.Internal, services.ErrUpdatingResource)
	}

	sql, args, err := updateAttributeSql(id, attr.Name, attributesRuleTypeEnumTransformIn(attr.Rule.String()), metadataJson)
	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, status.Error(codes.Internal, services.ErrUpdatingResource)
	}

	// return the attribute before updating
	return a, nil
}

func deleteAttributeSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete(AttributeTable).
		Where(sq.Eq{tableField(AttributeTable, "id"): id}).
		ToSql()
}
func (c Client) DeleteAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	// get attribute before deleting
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, status.Error(status.Code(err), services.ErrDeletingResource)
	}

	sql, args, err := deleteAttributeSql(id)

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, status.Error(codes.Internal, services.ErrDeletingResource)
	}

	// return the attribute before deleting
	return a, nil
}
