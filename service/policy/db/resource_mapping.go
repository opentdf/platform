package db

import (
	"context"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/internal/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func resourceMappingHydrateList(rows pgx.Rows) ([]*policy.ResourceMapping, error) {
	var list []*policy.ResourceMapping

	for rows.Next() {
		rm, err := resourceMappingHydrateItem(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, rm)
	}
	return list, nil
}

func resourceMappingHydrateItem(row pgx.Row) (*policy.ResourceMapping, error) {
	var (
		id                 string
		metadataJSON       []byte
		metadata           = new(common.Metadata)
		terms              []string
		attributeValueJSON []byte
		attributeValue     = new(policy.Value)
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

	if attributeValueJSON != nil {
		if err := protojson.Unmarshal(attributeValueJSON, attributeValue); err != nil {
			slog.Error("failed to unmarshal attribute value", slog.String("error", err.Error()), slog.String("attribute value JSON", string(attributeValueJSON)))
			return nil, err
		}
	}

	return &policy.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: attributeValue,
		Terms:          terms,
	}, nil
}

func resourceMappingSelect() sq.SelectBuilder {
	t := Tables.ResourceMappings
	at := Tables.AttributeValues
	members := "COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
		"'id', vmv.id, " +
		"'value', vmv.value, " +
		"'active', vmv.active, " +
		"'members', vmv.members || ARRAY[]::UUID[] " +
		")) FILTER (WHERE vmv.id IS NOT NULL ), '[]')"
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		constructMetadata(t.Name(), false),
		t.Field("terms"),
		"JSON_BUILD_OBJECT("+
			"'id', av.id,"+
			"'value', av.value,"+
			"'members', "+members+
			") AS attribute_value",
	).
		LeftJoin(at.Name() + " av ON " + t.Field("attribute_value_id") + " = " + "av.id").
		LeftJoin(Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id").
		LeftJoin(at.Name() + " vmv ON vm.member_id = vmv.id").
		GroupBy("av.id").
		GroupBy(t.Field("id"))
}

/*
 Resource Mapping CRUD
*/

func createResourceMappingSQL(attributeValueID string, metadata []byte, terms []string) (string, []interface{}, error) {
	return db.NewStatementBuilder().
		Insert(Tables.ResourceMappings.Name()).
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
		Suffix(createSuffix).
		ToSql()
}

func (c PolicyDBClient) CreateResourceMapping(ctx context.Context, r *resourcemapping.CreateResourceMappingRequest) (*policy.ResourceMapping, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	sql, args, err := createResourceMappingSQL(r.GetAttributeValueId(), metadataJSON, r.GetTerms())
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var id string
	if err := row.Scan(&id, &metadataJSON); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	av, err := c.GetAttributeValue(ctx, r.GetAttributeValueId())
	if err != nil {
		slog.Error("failed to get attribute value", "id", r.GetAttributeValueId(), "err", err)
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(metadataJSON, metadata); err != nil {
		return nil, err
	}

	return &policy.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: av,
		Terms:          r.GetTerms(),
	}, nil
}

func getResourceMappingSQL(id string) (string, []interface{}, error) {
	t := Tables.ResourceMappings
	return resourceMappingSelect().
		Where(sq.Eq{t.Field("id"): id}).
		From(Tables.ResourceMappings.Name()).
		ToSql()
}

func (c PolicyDBClient) GetResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	sql, args, err := getResourceMappingSQL(id)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
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
	t := Tables.ResourceMappings
	return resourceMappingSelect().
		From(t.Name()).
		ToSql()
}

func (c PolicyDBClient) ListResourceMappings(ctx context.Context) ([]*policy.ResourceMapping, error) {
	sql, args, err := listResourceMappingsSQL()
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
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
	t := Tables.ResourceMappings
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

func (c PolicyDBClient) UpdateResourceMapping(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingRequest) (*policy.ResourceMapping, error) {
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		rm, err := c.GetResourceMapping(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		return rm.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateResourceMappingSQL(
		id,
		r.GetAttributeValueId(),
		metadataJSON,
		r.GetTerms(),
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.ResourceMapping{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.ResourceMapping{
		Id: id,
	}, nil
}

func deleteResourceMappingSQL(id string) (string, []interface{}, error) {
	t := Tables.ResourceMappings
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDBClient) DeleteResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	prev, err := c.GetResourceMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	sql, args, err := deleteResourceMappingSQL(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return prev, nil
}
