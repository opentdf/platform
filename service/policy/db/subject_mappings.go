package db

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

// Helper to marshal SubjectSets into JSON (stored as JSONB in the database column)
func marshalSubjectSetsProto(subjectSet []*policy.SubjectSet) ([]byte, error) {
	var raw []json.RawMessage
	for _, ss := range subjectSet {
		b, err := protojson.Marshal(ss)
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
	}
	return json.Marshal(raw)
}

// Helper to unmarshal SubjectSets from JSON (stored as JSONB in the database column)
func unmarshalSubjectSetsProto(conditionJSON []byte, logger *logger.Logger) ([]*policy.SubjectSet, error) {
	var (
		raw []json.RawMessage
		ss  []*policy.SubjectSet
	)
	if err := json.Unmarshal(conditionJSON, &raw); err != nil {
		logger.Error("failed to unmarshal subject sets", slog.String("error", err.Error()), slog.String("condition JSON", string(conditionJSON)))
		return nil, err
	}

	for _, r := range raw {
		s := policy.SubjectSet{}
		if err := protojson.Unmarshal(r, &s); err != nil {
			logger.Error("failed to unmarshal subject set", slog.String("error", err.Error()), slog.String("subject set JSON", string(r)))
			return nil, err
		}
		ss = append(ss, &s)
	}

	return ss, nil
}

// Helper to marshal Actions into JSON (stored as JSONB in the database column)
func marshalActionsProto(actions []*policy.Action) ([]byte, error) {
	var raw []json.RawMessage
	for _, a := range actions {
		b, err := protojson.Marshal(a)
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
	}
	return json.Marshal(raw)
}

func unmarshalActionsProto(actionsJSON []byte, logger *logger.Logger) ([]*policy.Action, error) {
	var (
		raw     []json.RawMessage
		actions []*policy.Action
	)
	if err := json.Unmarshal(actionsJSON, &raw); err != nil {
		logger.Error("failed to unmarshal actions", slog.String("error", err.Error()), slog.String("actions JSON", string(actionsJSON)))
		return nil, err
	}

	for _, r := range raw {
		a := policy.Action{}
		if err := protojson.Unmarshal(r, &a); err != nil {
			logger.Error("failed to unmarshal action", slog.String("error", err.Error()), slog.String("action JSON", string(r)))
			return nil, err
		}
		actions = append(actions, &a)
	}
	return actions, nil
}

func subjectMappingSelect() sq.SelectBuilder {
	t := Tables.SubjectMappings
	avT := Tables.AttributeValues
	scsT := Tables.SubjectConditionSet
	adT := Tables.Attributes
	nsT := Tables.Namespaces
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("actions"),
		constructMetadata(t.Name(), false),
		"JSON_BUILD_OBJECT("+
			"'id', "+scsT.Field("id")+", "+
			constructMetadata(scsT.Name(), true)+
			"'subject_sets', "+scsT.Field("condition")+
			") AS subject_condition_set",
		"JSON_BUILD_OBJECT("+
			"'id', av.id,"+
			"'value', av.value,"+
			"'active', av.active"+
			") AS attribute_value",
	).
		LeftJoin(avT.Name() + " av ON " + t.Field("attribute_value_id") + " = " + "av.id").
		LeftJoin(adT.Name() + " ad ON av.attribute_definition_id = ad.id").
		LeftJoin(nsT.Name() + " ns ON ad.namespace_id = ns.id").
		GroupBy("av.id").
		GroupBy(t.Field("id")).
		LeftJoin(scsT.Name() + " ON " + scsT.Field("id") + " = " + t.Field("subject_condition_set_id")).
		GroupBy(scsT.Field("id"))
}

func subjectMappingHydrateItem(row pgx.Row, logger *logger.Logger) (*policy.SubjectMapping, error) {
	var (
		id                 string
		actionsJSON        []byte
		metadataJSON       []byte
		scsJSON            []byte
		attributeValueJSON []byte
	)

	err := row.Scan(
		&id,
		&actionsJSON,
		&metadataJSON,
		&scsJSON,
		&attributeValueJSON,
	)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			logger.Error("failed to unmarshal metadata", slog.String("error", err.Error()), slog.String("metadata JSON", string(metadataJSON)))
			return nil, err
		}
	}

	av := &policy.Value{}
	if attributeValueJSON != nil {
		if err := protojson.Unmarshal(attributeValueJSON, av); err != nil {
			logger.Error("failed to unmarshal attribute value", slog.String("error", err.Error()), slog.String("attribute value JSON", string(attributeValueJSON)))
			return nil, err
		}
	}

	a := []*policy.Action{}
	if actionsJSON != nil {
		if a, err = unmarshalActionsProto(actionsJSON, logger); err != nil {
			logger.Error("could not unmarshal actions", slog.String("error", err.Error()), slog.String("actions JSON", string(actionsJSON)))
			return nil, err
		}
	}

	scs := policy.SubjectConditionSet{}
	if scsJSON != nil {
		if err := protojson.Unmarshal(scsJSON, &scs); err != nil {
			logger.Error("could not unmarshal subject condition set", slog.String("error", err.Error()), slog.String("subject condition set JSON", string(scsJSON)))
			return nil, err
		}
	}

	return &policy.SubjectMapping{
		Id:                  id,
		Metadata:            m,
		AttributeValue:      av,
		SubjectConditionSet: &scs,
		Actions:             a,
	}, nil
}

func subjectMappingHydrateList(rows pgx.Rows, logger *logger.Logger) ([]*policy.SubjectMapping, error) {
	list := make([]*policy.SubjectMapping, 0)
	for rows.Next() {
		s, err := subjectMappingHydrateItem(rows, logger)
		if err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, nil
}

/*
	Subject Condition Sets
*/

// Creates a new subject condition set and returns the id of the created
func (c PolicyDBClient) CreateSubjectConditionSet(ctx context.Context, s *subjectmapping.SubjectConditionSetCreate) (*policy.SubjectConditionSet, error) {
	conditionJSON, err := marshalSubjectSetsProto(s.GetSubjectSets())
	if err != nil {
		c.logger.ErrorContext(ctx, "could not marshal subject sets", slog.String("error", err.Error()))
		return nil, err
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.GetMetadata())
	if err != nil {
		return nil, err
	}

	cs, err := c.Queries.CreateSubjectConditionSet(ctx, CreateSubjectConditionSetParams{
		Condition: conditionJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(cs.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.SubjectConditionSet{
		Id:          cs.ID,
		SubjectSets: s.GetSubjectSets(),
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) GetSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	cs, err := c.Queries.GetSubjectConditionSet(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(cs.Metadata, metadata); err != nil {
		return nil, err
	}

	sets, err := unmarshalSubjectSetsProto(cs.Condition, c.logger)
	if err != nil {
		return nil, err
	}

	return &policy.SubjectConditionSet{
		Id:          id,
		SubjectSets: sets,
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) ListSubjectConditionSets(ctx context.Context) ([]*policy.SubjectConditionSet, error) {
	list, err := c.Queries.ListSubjectConditionSets(ctx)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	setList := make([]*policy.SubjectConditionSet, len(list))
	for i, set := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(set.Metadata, metadata); err != nil {
			return nil, err
		}

		sets, err := unmarshalSubjectSetsProto(set.Condition, c.logger)
		if err != nil {
			return nil, err
		}

		setList[i] = &policy.SubjectConditionSet{
			Id:          set.ID,
			SubjectSets: sets,
			Metadata:    metadata,
		}
	}

	return setList, nil
}

// Mutates provided fields and returns id of the updated subject condition set
func (c PolicyDBClient) UpdateSubjectConditionSet(ctx context.Context, r *subjectmapping.UpdateSubjectConditionSetRequest) (*policy.SubjectConditionSet, error) {
	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		scs, err := c.GetSubjectConditionSet(ctx, r.GetId())
		if err != nil {
			return nil, err
		}
		return scs.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var conditionJSON []byte
	if r.SubjectSets != nil {
		conditionJSON, err = marshalSubjectSetsProto(r.GetSubjectSets())
		if err != nil {
			c.logger.ErrorContext(ctx, "failed to marshal subject sets", slog.String("error", err.Error()))
			return nil, err
		}
	}

	updatedID, err := c.Queries.UpdateSubjectConditionSet(ctx, UpdateSubjectConditionSetParams{
		ID:        r.GetId(),
		Condition: conditionJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectConditionSet{
		Id: updatedID,
	}, nil
}

// Deletes specified subject condition set and returns the id of the deleted
func (c PolicyDBClient) DeleteSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	count, err := c.Queries.DeleteSubjectConditionSet(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectConditionSet{
		Id: id,
	}, nil
}

/*
	Subject Mappings
*/

// Creates a new subject mapping and returns the id of the created. If an existing subject condition set id is provided, it will be used.
// If a new subject condition set is provided, it will be created. The existing subject condition set id takes precedence.
func (c PolicyDBClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.CreateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	var (
		scs *policy.SubjectConditionSet
		err error
	)

	// Prefer existing id over new creation per documented proto behavior.
	switch {
	case s.GetExistingSubjectConditionSetId() != "":
		scs, err = c.GetSubjectConditionSet(ctx, s.GetExistingSubjectConditionSetId())
		if err != nil {
			return nil, err
		}
	case s.GetNewSubjectConditionSet() != nil:
		// create the new subject condition set
		scs, err = c.CreateSubjectConditionSet(ctx, s.GetNewSubjectConditionSet())
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Join(db.ErrMissingValue, errors.New("either an existing Subject Condition Set ID or a new Subject Condition Set is required when creating a subject mapping"))
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.GetMetadata())
	if err != nil {
		return nil, err
	}
	if s.Actions == nil {
		return nil, errors.Join(db.ErrMissingValue, errors.New("actions are required when creating a subject mapping"))
	}
	actionsJSON, err := marshalActionsProto(s.GetActions())
	if err != nil {
		return nil, err
	}

	uuidScsID, err := uuid.Parse(scs.GetId())
	pgScsID := pgtype.UUID{
		Bytes: [16]byte(uuidScsID),
		Valid: err == nil,
	}

	sm, err := c.Queries.CreateSubjectMapping(ctx, CreateSubjectMappingParams{
		AttributeValueID:      s.GetAttributeValueId(),
		Actions:               actionsJSON,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgScsID,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(metadataJSON, metadata); err != nil {
		return nil, err
	}

	return &policy.SubjectMapping{
		Id: sm.ID,
		AttributeValue: &policy.Value{
			Id: s.GetAttributeValueId(),
		},
		SubjectConditionSet: scs,
		Actions:             s.GetActions(),
		Metadata:            metadata,
	}, nil
}

func (c PolicyDBClient) GetSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	sm, err := c.Queries.GetSubjectMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(sm.Metadata, metadata); err != nil {
		return nil, err
	}

	av := &policy.Value{}
	if sm.AttributeValue != nil {
		if err := protojson.Unmarshal(sm.AttributeValue, av); err != nil {
			c.logger.ErrorContext(ctx, "failed to unmarshal attribute value",
				slog.String("error", err.Error()),
				slog.String("attribute value JSON", string(sm.AttributeValue)),
			)
			return nil, err
		}
	}

	a := []*policy.Action{}
	if sm.Actions != nil {
		if a, err = unmarshalActionsProto(sm.Actions, c.logger); err != nil {
			return nil, err
		}
	}

	scs := policy.SubjectConditionSet{}
	if sm.SubjectConditionSet != nil {
		if err := protojson.Unmarshal(sm.SubjectConditionSet, &scs); err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal subject condition set",
				slog.String("error", err.Error()),
				slog.String("subject condition set JSON", string(sm.SubjectConditionSet)),
			)
			return nil, err
		}
	}

	return &policy.SubjectMapping{
		Id:                  id,
		Metadata:            metadata,
		AttributeValue:      av,
		SubjectConditionSet: &scs,
		Actions:             a,
	}, nil
}

func (c PolicyDBClient) ListSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	list, err := c.Queries.ListSubjectMappings(ctx)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappings := make([]*policy.SubjectMapping, len(list))
	for i, sm := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(sm.Metadata, metadata); err != nil {
			return nil, err
		}

		av := &policy.Value{}
		if sm.AttributeValue != nil {
			if err := protojson.Unmarshal(sm.AttributeValue, av); err != nil {
				c.logger.ErrorContext(ctx, "failed to unmarshal attribute value",
					slog.String("error", err.Error()),
					slog.String("attribute value JSON", string(sm.AttributeValue)),
				)
				return nil, err
			}
		}

		a := []*policy.Action{}
		if sm.Actions != nil {
			if a, err = unmarshalActionsProto(sm.Actions, c.logger); err != nil {
				return nil, err
			}
		}

		scs := policy.SubjectConditionSet{}
		if sm.SubjectConditionSet != nil {
			if err := protojson.Unmarshal(sm.SubjectConditionSet, &scs); err != nil {
				c.logger.ErrorContext(ctx, "could not unmarshal subject condition set",
					slog.String("error", err.Error()),
					slog.String("subject condition set JSON", string(sm.SubjectConditionSet)),
				)
				return nil, err
			}
		}

		mappings[i] = &policy.SubjectMapping{
			Id:                  sm.ID,
			Metadata:            metadata,
			AttributeValue:      av,
			SubjectConditionSet: &scs,
			Actions:             a,
		}
	}

	return mappings, nil
}

// Mutates provided fields and returns id of the updated subject mapping
func (c PolicyDBClient) UpdateSubjectMapping(ctx context.Context, r *subjectmapping.UpdateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetSubjectMapping(ctx, r.GetId())
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var actionsJSON []byte
	if r.Actions != nil {
		actionsJSON, err = marshalActionsProto(r.GetActions())
		if err != nil {
			return nil, err
		}
	}

	uuidScsID, err := uuid.Parse(r.GetSubjectConditionSetId())
	pgScsID := pgtype.UUID{
		Bytes: [16]byte(uuidScsID),
		Valid: err == nil,
	}

	updatedID, err := c.Queries.UpdateSubjectMapping(ctx, UpdateSubjectMappingParams{
		ID:                    r.GetId(),
		Actions:               actionsJSON,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgScsID,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectMapping{
		Id: updatedID,
	}, nil
}

// Deletes specified subject mapping and returns the id of the deleted
func (c PolicyDBClient) DeleteSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	count, err := c.Queries.DeleteSubjectMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectMapping{
		Id: id,
	}, nil
}

// This function generates a SQL select statement for SubjectMappings that based on external Subject property fields & values. This relationship
// is sometimes called Entitlements or Subject Entitlements.
//
// There is complexity in the SQL generation due to the external fields/values being stored in a JSONB column on the subject_condition_set table
// and the JSON structure being SubjectSets -> ConditionGroups -> Conditions.
//
// Unfortunately we must do some slight filtering at the SQL level to avoid extreme and potentially non-rare edge cases. Subject Mappings will
// be returned if there is any condition found among the structures that matches:
// 1. The external field, external value, and an IN operator
// 2. The external field, _no_ external value, and a NOT_IN operator
//
// Without this filtering, if a selector value was something like '.emailAddress' or '.username', every Subject is probably going to relate to that mapping
// in some way or another. This could theoretically be every attribute in the DB if a policy admin has relied heavily on that field.
//
// NOTE: if you have any issues, set the log level to 'debug' for more comprehensive context.
func selectMatchedSubjectMappingsSQL(subjectProperties []*policy.SubjectProperty, logger *logger.Logger) (string, []interface{}, error) {
	var err error
	if len(subjectProperties) == 0 {
		err = errors.Join(db.ErrMissingValue, errors.New("one or more subject properties is required"))
		logger.Error("subject property missing required value", slog.Any("properties provided", subjectProperties), slog.String("error", err.Error()))
		return "", nil, err
	}
	where := "("
	for i, sp := range subjectProperties {
		if sp.GetExternalSelectorValue() == "" || sp.GetExternalValue() == "" {
			err = errors.Join(db.ErrMissingValue, errors.New("all subject properties must include defined external selector value and value"))
			logger.Error("subject property missing required value", slog.Any("properties provided", subjectProperties), slog.String("error", err.Error()))
			return "", nil, err
		}
		if i > 0 {
			where += " OR "
		}

		hasField := "each_condition->>'subject_external_selector_value' = '" + sp.GetExternalSelectorValue() + "'"
		hasValue := "(each_condition->>'subject_external_values')::jsonb @> '[\"" + sp.GetExternalValue() + "\"]'::jsonb"
		hasInOperator := "each_condition->>'operator' = 'SUBJECT_MAPPING_OPERATOR_ENUM_IN'"
		hasNotInOperator := "each_condition->>'operator' = 'SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN'"
		// Parses the json and matches the row if either of the following conditions are met:
		where += "((" + hasField + " AND " + hasValue + " AND " + hasInOperator + ")" +
			" OR " +
			"(" + hasField + " AND NOT " + hasValue + " AND " + hasNotInOperator + "))"
		logger.Debug("current condition filter WHERE clause", slog.String("subject_external_selector_value", sp.GetExternalSelectorValue()), slog.String("subject_external_value", sp.GetExternalValue()), slog.String("where", where))
	}
	where += ")"

	t := Tables.SubjectConditionSet
	smT := Tables.SubjectMappings

	whereSubQ, _, err := db.NewStatementBuilder().
		// SELECT 1 is consumed by EXISTS clause, not true selection of data
		Select("1").
		From("jsonb_array_elements(" + t.Field("condition") + ") AS ss" +
			", jsonb_array_elements(ss->'condition_groups') AS cg" +
			", jsonb_array_elements(cg->'conditions') AS each_condition").
		Where(where).
		ToSql()
	if err != nil {
		logger.Error("could not generate SQL for subject entitlements", slog.String("error", err.Error()))
		return "", nil, err
	}
	logger.Debug("checking for existence of any condition in the SubjectSets > ConditionGroups > Conditions that matches the provided subject properties", slog.String("where", whereSubQ))

	return subjectMappingSelect().
		From(smT.Name()).
		// ensure namespace, definition, and value of mapped attribute are all active
		Where("ns.active = true AND ad.active = true AND av.active = true AND EXISTS (" + whereSubQ + ")").
		ToSql()
}

// GetMatchedSubjectMappings liberally returns a list of SubjectMappings based on the provided SubjectProperties. The SubjectMappings are returned
// if there is any single condition found among the structures that matches:
// 1. The external field, external value, and an IN operator
// 2. The external field, _no_ external value, and a NOT_IN operator
//
// Without this filtering, if a field was something like '.emailAddress' or '.username', every Subject is probably going to relate to that mapping
// in some way or another, potentially matching every single attribute in the DB if a policy admin has relied heavily on that field. There is no
// logic applied beyond a single condition within the query to avoid business logic interpreting the supplied conditions beyond the bare minimum
// initial filter.
//
// NOTE: This relationship is sometimes called Entitlements or Subject Entitlements.
// NOTE: if you have any issues, set the log level to 'debug' for more comprehensive context.
func (c PolicyDBClient) GetMatchedSubjectMappings(ctx context.Context, properties []*policy.SubjectProperty) ([]*policy.SubjectMapping, error) {
	sql, args, err := selectMatchedSubjectMappingsSQL(properties, c.logger)
	c.logger.Debug("generated SQL for subject entitlements", slog.Any("properties", properties), slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	c.logger.Debug("executed SQL for subject entitlements", slog.Any("properties", properties), slog.String("sql", sql), slog.Any("args", args), slog.Any("rows", rows), slog.Any("error", err))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return subjectMappingHydrateList(rows, c.logger)
}
