package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/sdk/resourcemapping"
	"google.golang.org/protobuf/encoding/protojson"
)

var ResourceMappingTable = tableName(TableResourceMappings)

func resourceMappingHydrateList(rows pgx.Rows) ([]*resourcemapping.ResourceMapping, error) {
	var list []*resourcemapping.ResourceMapping

	for rows.Next() {
		rm, err := resourceMappingHydrateItem(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, rm)
	}
	return list, nil
}

func resourceMappingHydrateItem(row pgx.Row) (*resourcemapping.ResourceMapping, error) {
	var (
		id                 string
		metadataJSON       []byte
		metadata           = new(common.Metadata)
		terms              []string
		attributeValueJSON []byte
		attributeValue     = new(attributes.Value)
	)

	err := row.Scan(
		&id,
		&metadataJSON,
		&terms,
		&attributeValueJSON,
	)
	if err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	if metadataJSON != nil {
		err = protojson.Unmarshal(metadataJSON, metadata)
		if err != nil {
			return nil, err
		}
	}

	err = protojson.Unmarshal(attributeValueJSON, attributeValue)
	if err != nil {
		return nil, err
	}

	return &resourcemapping.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: attributeValue,
		Terms:          terms,
	}, nil
}

func resourceMappingSelect() sq.SelectBuilder {
	t := Tables.ResourceMappings
	aT := Tables.AttributeValues
	return newStatementBuilder().Select(
		t.Field("id"),
		t.Field("metadata"),
		t.Field("terms"),
		"JSON_BUILD_OBJECT("+
			"'id', "+aT.Field("id")+", "+
			"'value', "+aT.Field("value")+","+
			"'members', "+aT.Field("members")+
			")"+
			" AS attribute_value",
	).
		LeftJoin(AttributeValueTable+" ON "+aT.Field("id")+" = "+t.Field("attribute_value_id")).
		GroupBy(t.Field("id"), aT.Field("id"))
}

/*
 Resource Mapping CRUD
*/

func createResourceMappingSQL(attributeValueID string, metadata []byte, terms []string) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(ResourceMappingTable).
		Columns(
			"attribute_value_id",
			"metadata",
			"terms",
		).
		Values(
			attributeValueID,
			metadata,
			terms,
		).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) CreateResourceMapping(ctx context.Context, rm *resourcemapping.ResourceMappingCreateUpdate) (*resourcemapping.ResourceMapping, error) {
	metadataJSON, metadata, err := marshalCreateMetadata(rm.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createResourceMappingSQL(rm.AttributeValueId, metadataJSON, rm.Terms)
	if err != nil {
		return nil, err
	}

	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	var id string
	if err := row.Scan(&id); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	av, err := c.GetAttributeValue(ctx, rm.AttributeValueId)
	if err != nil {
		return nil, err
	}

	return &resourcemapping.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: av,
		Terms:          rm.Terms,
	}, nil
}

func getResourceMappingSQL(id string) (string, []interface{}, error) {
	t := Tables.ResourceMappings
	return resourceMappingSelect().
		Where(sq.Eq{t.Field("id"): id}).
		From(ResourceMappingTable).
		ToSql()
}

func (c Client) GetResourceMapping(ctx context.Context, id string) (*resourcemapping.ResourceMapping, error) {
	sql, args, err := getResourceMappingSQL(id)

	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	rm, err := resourceMappingHydrateItem(row)
	if err != nil {
		return nil, err
	}
	return rm, nil
}

func listResourceMappingsSQL() (string, []interface{}, error) {
	t := Tables.ResourceMappings
	return resourceMappingSelect().
		From(t.Name()).
		ToSql()
}

func (c Client) ListResourceMappings(ctx context.Context) ([]*resourcemapping.ResourceMapping, error) {
	sql, args, err := listResourceMappingsSQL()
	if err != nil {
		return nil, err
	}

	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list, err := resourceMappingHydrateList(rows)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func updateResourceMappingSQL(id string, attribute_value_id string, metadata []byte, terms []string) (string, []interface{}, error) {
	t := Tables.ResourceMappings
	sb := newStatementBuilder().
		Update(t.Name())

	if attribute_value_id != "" {
		sb = sb.Set("attribute_value_id", attribute_value_id)
	}

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	if terms != nil {
		sb = sb.Set("terms", terms)
	}

	return sb.
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) UpdateResourceMapping(ctx context.Context, id string, rm *resourcemapping.ResourceMappingCreateUpdate) (*resourcemapping.ResourceMapping, error) {
	prev, err := c.GetResourceMapping(ctx, id)
	if err != nil {
		return nil, err
	}

	metadataJSON, _, err := marshalUpdateMetadata(prev.Metadata, rm.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateResourceMappingSQL(
		id,
		rm.AttributeValueId,
		metadataJSON,
		rm.Terms,
	)
	if err != nil {
		return nil, err
	}

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}

func deleteResourceMappingSQL(id string) (string, []interface{}, error) {
	t := Tables.ResourceMappings
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c Client) DeleteResourceMapping(ctx context.Context, id string) (*resourcemapping.ResourceMapping, error) {
	prev, err := c.GetResourceMapping(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteResourceMappingSQL(id)
	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}
