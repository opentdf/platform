package db

import (
	"context"
	"errors"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/util"
	"google.golang.org/protobuf/encoding/protojson"
)

/*
 Resource Mapping CRUD

 NOTE: uses sqlc instead of squirrel
*/

func (c PolicyDBClient) ListResourceMappingGroups(ctx context.Context, r *resourcemapping.ListResourceMappingGroupsRequest) ([]*policy.ResourceMappingGroup, error) {
	list, err := c.Queries.ListResourceMappingGroups(ctx, r.GetNamespaceId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	resourceMappingGroups := make([]*policy.ResourceMappingGroup, len(list))

	for i, rmGroup := range list {
		resourceMappingGroups[i] = &policy.ResourceMappingGroup{
			Id:          rmGroup.ID,
			NamespaceId: rmGroup.NamespaceID,
			Name:        rmGroup.Name,
		}
	}

	return resourceMappingGroups, nil
}

func (c PolicyDBClient) ListResourceMappingGroupsByFqns(ctx context.Context, fqns []string) (map[string]*policy.ResourceMappingGroup, error) {
	resp := make(map[string]*policy.ResourceMappingGroup)
	resultCount := 0

	for _, fqn := range fqns {
		fullyQualifiedRmg, err := util.ParseResourceMappingGroupFqn(fqn)
		if err != nil {
			// invalid FQNs not included in the response - ignore and continue, but log for investigation
			slog.DebugContext(ctx, "error parsing Resource Mapping Group FQN", slog.String("rmg_fqn", fqn))
			continue
		}

		rmGroup, err := c.Queries.GetResourceMappingGroupFullyQualified(ctx, GetResourceMappingGroupFullyQualifiedParams{
			NamespaceName: fullyQualifiedRmg.Namespace,
			GroupName:     fullyQualifiedRmg.GroupName,
		})
		if err != nil {
			dbErr := db.WrapIfKnownInvalidQueryErr(err)
			if errors.Is(dbErr, db.ErrNotFound) {
				// FQN is valid but not in db, so indicate it was not found with nil value
				resp[fqn] = nil
				continue
			}

			return nil, dbErr
		}

		resultCount++

		resp[fqn] = &policy.ResourceMappingGroup{
			Id:          rmGroup.ID,
			NamespaceId: rmGroup.NamespaceID,
			Name:        rmGroup.Name,
		}
	}

	if resultCount == 0 {
		// should return an error if none of the FQNs are found
		return nil, db.ErrNotFound
	}

	return resp, nil
}

func (c PolicyDBClient) GetResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	rmGroup, err := c.Queries.GetResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id:          rmGroup.ID,
		NamespaceId: rmGroup.NamespaceID,
		Name:        rmGroup.Name,
	}, nil
}

func (c PolicyDBClient) CreateResourceMappingGroup(ctx context.Context, r *resourcemapping.CreateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	createdID, err := c.Queries.CreateResourceMappingGroup(ctx, CreateResourceMappingGroupParams{
		NamespaceID: r.GetNamespaceId(),
		Name:        r.GetName(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id: createdID,
	}, nil
}

func (c PolicyDBClient) UpdateResourceMappingGroup(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	uuidNamespaceID, err := uuid.Parse(r.GetNamespaceId())
	pgNamespaceID := pgtype.UUID{
		Bytes: [16]byte(uuidNamespaceID),
		Valid: err == nil,
	}

	name := r.GetName()
	pgName := pgtype.Text{
		String: name,
		Valid:  name != "",
	}

	updatedID, err := c.Queries.UpdateResourceMappingGroup(ctx, UpdateResourceMappingGroupParams{
		ID:          id,
		NamespaceID: pgNamespaceID,
		Name:        pgName,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id: updatedID,
	}, nil
}

func (c PolicyDBClient) DeleteResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	count, err := c.Queries.DeleteResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.ResourceMappingGroup{
		Id: id,
	}, nil
}

/*
 Resource Mapping CRUD

 TODO: migrate from squirrel to sqlc
*/

func resourceMappingHydrateList(rows pgx.Rows, logger *logger.Logger) ([]*policy.ResourceMapping, error) {
	var list []*policy.ResourceMapping

	for rows.Next() {
		rm, err := resourceMappingHydrateItem(rows, logger)
		if err != nil {
			return nil, err
		}
		list = append(list, rm)
	}
	return list, nil
}

func resourceMappingHydrateItem(row pgx.Row, logger *logger.Logger) (*policy.ResourceMapping, error) {
	var (
		id                 string
		metadataJSON       []byte
		metadata           = new(common.Metadata)
		terms              []string
		attributeValueJSON []byte
		attributeValue     = new(policy.Value)
		groupID            string
	)

	err := row.Scan(
		&id,
		&metadataJSON,
		&terms,
		&attributeValueJSON,
		&groupID,
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
			logger.Error("failed to unmarshal attribute value", slog.String("error", err.Error()), slog.String("attribute value JSON", string(attributeValueJSON)))
			return nil, err
		}
	}

	rm := &policy.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: attributeValue,
		Terms:          terms,
	}

	if groupID != "" {
		rm.Group = &policy.ResourceMappingGroup{Id: groupID}
	}

	return rm, nil
}

func resourceMappingSelect() sq.SelectBuilder {
	t := Tables.ResourceMappings
	at := Tables.AttributeValues
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		constructMetadata(t.Name(), false),
		t.Field("terms"),
		"JSON_BUILD_OBJECT("+
			"'id', av.id,"+
			"'value', av.value "+
			") AS attribute_value",
		"COALESCE("+t.Field("group_id")+"::TEXT, '') AS group_id",
	).
		LeftJoin(at.Name() + " av ON " + t.Field("attribute_value_id") + " = " + "av.id").
		GroupBy("av.id").
		GroupBy(t.Field("id"))
}

func createResourceMappingSQL(attributeValueID string, metadata []byte, terms []string, groupID string) (string, []interface{}, error) {
	columns := []string{"attribute_value_id", "metadata", "terms"}
	values := []interface{}{attributeValueID, metadata, terms}

	if groupID != "" {
		columns = append(columns, "group_id")
		values = append(values, groupID)
	}

	return db.NewStatementBuilder().
		Insert(Tables.ResourceMappings.Name()).
		Columns(columns...).
		Values(values...).
		Suffix(createSuffix).
		ToSql()
}

func (c PolicyDBClient) CreateResourceMapping(ctx context.Context, r *resourcemapping.CreateResourceMappingRequest) (*policy.ResourceMapping, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	groupID := r.GetGroupId()

	sql, args, err := createResourceMappingSQL(r.GetAttributeValueId(), metadataJSON, r.GetTerms(), groupID)
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
		c.logger.Error("failed to get attribute value", "id", r.GetAttributeValueId(), "err", err)
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(metadataJSON, metadata, c.logger); err != nil {
		return nil, err
	}

	rm := &policy.ResourceMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: av,
		Terms:          r.GetTerms(),
	}

	if groupID != "" {
		rm.Group = &policy.ResourceMappingGroup{Id: groupID}
	}

	return rm, nil
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

	rm, err := resourceMappingHydrateItem(row, c.logger)
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

	list, err := resourceMappingHydrateList(rows, c.logger)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return list, nil
}

func updateResourceMappingSQL(id string, attributeValueID string, metadata []byte, terms []string, groupID string) (string, []interface{}, error) {
	t := Tables.ResourceMappings
	sb := db.NewStatementBuilder().
		Update(t.Name())

	if attributeValueID != "" {
		sb = sb.Set("attribute_value_id", attributeValueID)
	}

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	if terms != nil {
		sb = sb.Set("terms", terms)
	}

	if groupID != "" {
		sb = sb.Set("group_id", groupID)
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
		r.GetGroupId(),
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
