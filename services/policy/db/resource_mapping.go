package db

import (
	"context"
	"fmt"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"google.golang.org/protobuf/encoding/protojson"
)

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
		return nil, db.WrapIfKnownInvalidQueryErr(err)
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
	t := db.Tables.ResourceMappings
	at := db.Tables.AttributeValues
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("metadata"),
		t.Field("terms"),
		"JSON_BUILD_OBJECT("+
			"'id', "+at.Field("id")+", "+
			"'value', "+at.Field("value")+","+
			"'members', "+at.Field("members")+
			")"+
			" AS attribute_value",
	).
		LeftJoin(at.Name()+" ON "+at.Field("id")+" = "+t.Field("attribute_value_id")).
		GroupBy(t.Field("id"), at.Field("id"))
}

/*
 Resource Mapping CRUD
*/

func createResourceMappingSQL(attributeValueID string, metadata []byte, terms []string) (string, []interface{}, error) {
	return db.NewStatementBuilder().
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

func (c PolicyDbClient) CreateResourceMapping(ctx context.Context, r *resourcemapping.CreateResourceMappingRequest) (*resourcemapping.ResourceMapping, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createResourceMappingSQL(r.AttributeValueId, metadataJSON, r.Terms)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var id string
	if err := row.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	av, err := c.GetAttributeValue(ctx, r.AttributeValueId)
	if err != nil {
		slog.Error("failed to get attribute value", "id", r.AttributeValueId, "err", err)
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &resourcemapping.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: av,
		Terms:          r.Terms,
	}, nil
}

func getResourceMappingSQL(id string) (string, []interface{}, error) {
	t := db.Tables.ResourceMappings
	return resourceMappingSelect().
		Where(sq.Eq{t.Field("id"): id}).
		From(ResourceMappingTable).
		ToSql()
}

func (c PolicyDbClient) GetResourceMapping(ctx context.Context, id string) (*resourcemapping.ResourceMapping, error) {
	sql, args, err := getResourceMappingSQL(id)

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	rm, err := resourceMappingHydrateItem(row)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	return rm, nil
}

func listResourceMappingsSQL() (string, []interface{}, error) {
	t := db.Tables.ResourceMappings
	return resourceMappingSelect().
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) ListResourceMappings(ctx context.Context) ([]*resourcemapping.ResourceMapping, error) {
	sql, args, err := listResourceMappingsSQL()
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := resourceMappingHydrateList(rows)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return list, nil
}

func updateResourceMappingSQL(id string, attribute_value_id string, metadata []byte, terms []string) (string, []interface{}, error) {
	t := db.Tables.ResourceMappings
	sb := db.NewStatementBuilder().
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

func (c PolicyDbClient) UpdateResourceMapping(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingRequest) (*resourcemapping.ResourceMapping, error) {
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.Metadata, r.MetadataUpdateBehavior, func() (*common.Metadata, error) {
		rm, err := c.GetResourceMapping(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		return rm.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateResourceMappingSQL(
		id,
		r.AttributeValueId,
		metadataJSON,
		r.Terms,
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &resourcemapping.ResourceMapping{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		fmt.Printf("err: %v %v\n", err, args)
		return nil, err
	}

	return &resourcemapping.ResourceMapping{
		Id: id,
	}, nil
}

func deleteResourceMappingSQL(id string) (string, []interface{}, error) {
	t := db.Tables.ResourceMappings
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) DeleteResourceMapping(ctx context.Context, id string) (*resourcemapping.ResourceMapping, error) {
	prev, err := c.GetResourceMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	sql, args, err := deleteResourceMappingSQL(id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return prev, nil
}
