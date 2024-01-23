package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/opentdf/opentdf-v2-poc/sdk/resourcemapping"
)

var ResourceMappingTable = tableName(TableResourceMappings)

func resourceMappingSelect() sq.SelectBuilder {
	return newStatementBuilder().Select(
		tableField(ResourceMappingTable, "id"),
		tableField(ResourceMappingTable, "metadata"),
		tableField(ResourceMappingTable, "terms"),
		"JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', "+tableField(AttributeValueTable, "id")+", "+
			"'value', "+tableField(AttributeValueTable, "value")+","+
			"'members', "+tableField(AttributeValueTable, "members")+
			")"+
			") AS attribute_value",
	).
		LeftJoin(AttributeValueTable + " ON " + tableField(AttributeValueTable, "id") + " = " + tableField(ResourceMappingTable, "id")).
		GroupBy(tableField(ResourceMappingTable, "id"))
}

/*
 Resource Mapping CRUD
*/

func createResourceMappingSQL(attributeValueID string, metadata []byte, terms []string) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(ResourceMappingTable).
		Columns(
			tableField(ResourceMappingTable, "id"),
			tableField(ResourceMappingTable, "metadata"),
			tableField(ResourceMappingTable, "terms"),
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
		return nil, err
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
