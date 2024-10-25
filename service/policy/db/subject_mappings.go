package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
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
			// todo: can ss be included in the error message?
			return nil, fmt.Errorf("failed to marshall subject set: %w", err)
		}
		raw = append(raw, b)
	}
	return json.Marshal(raw)
}

// Helper to unmarshal SubjectSets from JSON (stored as JSONB in the database column)
func unmarshalSubjectSetsProto(conditionJSON []byte) ([]*policy.SubjectSet, error) {
	var (
		raw []json.RawMessage
		ss  []*policy.SubjectSet
	)
	if err := json.Unmarshal(conditionJSON, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subject sets array [%s]: %w", string(conditionJSON), err)
	}

	for _, r := range raw {
		s := policy.SubjectSet{}
		if err := protojson.Unmarshal(r, &s); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subject set [%s]: %w", string(r), err)
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

func unmarshalActionsProto(actionsJSON []byte, actions *[]*policy.Action) error {
	var raw []json.RawMessage

	if actionsJSON != nil {
		if err := json.Unmarshal(actionsJSON, &raw); err != nil {
			return fmt.Errorf("failed to unmarshal actions array [%s]: %w", string(actionsJSON), err)
		}

		for _, r := range raw {
			a := policy.Action{}
			if err := protojson.Unmarshal(r, &a); err != nil {
				return fmt.Errorf("failed to unmarshal action [%s]: %w", string(r), err)
			}
			*actions = append(*actions, &a)
		}
	}

	return nil
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

func subjectMappingHydrateItem(row pgx.Row) (*policy.SubjectMapping, error) {
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
	if err = unmarshalMetadata(metadataJSON, m); err != nil {
		return nil, err
	}

	av := &policy.Value{}
	if err = unmarshalAttributeValue(attributeValueJSON, av); err != nil {
		return nil, err
	}

	a := []*policy.Action{}
	if err = unmarshalActionsProto(actionsJSON, &a); err != nil {
		return nil, err
	}

	scs := policy.SubjectConditionSet{}
	if err = unmarshalSubjectConditionSet(scsJSON, &scs); err != nil {
		return nil, err
	}

	return &policy.SubjectMapping{
		Id:                  id,
		Metadata:            m,
		AttributeValue:      av,
		SubjectConditionSet: &scs,
		Actions:             a,
	}, nil
}

func subjectMappingHydrateList(rows pgx.Rows) ([]*policy.SubjectMapping, error) {
	list := make([]*policy.SubjectMapping, 0)
	for rows.Next() {
		s, err := subjectMappingHydrateItem(rows)
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

// Creates a new subject condition set and returns it
func (c PolicyDBClient) CreateSubjectConditionSet(ctx context.Context, s *subjectmapping.SubjectConditionSetCreate) (*policy.SubjectConditionSet, error) {
	subjectSets := s.GetSubjectSets()
	conditionJSON, err := marshalSubjectSetsProto(subjectSets)
	if err != nil {
		return nil, err
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateSubjectConditionSet(ctx, CreateSubjectConditionSetParams{
		Condition: conditionJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectConditionSet{
		Id:          createdID,
		SubjectSets: subjectSets,
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

	sets, err := unmarshalSubjectSetsProto(cs.Condition)
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

		sets, err := unmarshalSubjectSetsProto(set.Condition)
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

// Mutates provided fields and returns the updated subject condition set
func (c PolicyDBClient) UpdateSubjectConditionSet(ctx context.Context, r *subjectmapping.UpdateSubjectConditionSetRequest) (*policy.SubjectConditionSet, error) {
	id := r.GetId()
	subjectSets := r.GetSubjectSets()
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		scs, err := c.GetSubjectConditionSet(ctx, id)
		if err != nil {
			return nil, err
		}
		return scs.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var conditionJSON []byte
	if subjectSets != nil {
		conditionJSON, err = marshalSubjectSetsProto(subjectSets)
		if err != nil {
			return nil, err
		}
	}

	count, err := c.Queries.UpdateSubjectConditionSet(ctx, UpdateSubjectConditionSetParams{
		ID:        id,
		Condition: conditionJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectConditionSet{
		Id:          id,
		SubjectSets: subjectSets,
		Metadata:    metadata,
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

// Deletes/prunes all subject condition sets not referenced within a subject mapping
func (c PolicyDBClient) DeleteAllUnmappedSubjectConditionSets(ctx context.Context) ([]*policy.SubjectConditionSet, error) {
	deletedIDs, err := c.Queries.DeleteAllUnmappedSubjectConditionSets(ctx)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if len(deletedIDs) == 0 {
		return nil, db.ErrNotFound
	}

	setList := make([]*policy.SubjectConditionSet, len(deletedIDs))
	for i, id := range deletedIDs {
		setList[i] = &policy.SubjectConditionSet{
			Id: id,
		}
	}
	return setList, nil
}

/*
	Subject Mappings
*/

// Creates a new subject mapping and returns it. If an existing subject condition set id is provided, it will be used.
// If a new subject condition set is provided, it will be created. The existing subject condition set id takes precedence.
func (c PolicyDBClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.CreateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	actions := s.GetActions()
	attributeValueID := s.GetAttributeValueId()

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

	actionsJSON, err := marshalActionsProto(actions)
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateSubjectMapping(ctx, CreateSubjectMappingParams{
		AttributeValueID:      attributeValueID,
		Actions:               actionsJSON,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgtypeUUID(scs.GetId()),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectMapping{
		Id: createdID,
		AttributeValue: &policy.Value{
			Id: attributeValueID,
		},
		SubjectConditionSet: scs,
		Actions:             actions,
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
	if err = unmarshalAttributeValue(sm.AttributeValue, av); err != nil {
		return nil, err
	}

	a := []*policy.Action{}
	if err = unmarshalActionsProto(sm.Actions, &a); err != nil {
		return nil, err
	}

	scs := policy.SubjectConditionSet{}
	if err = unmarshalSubjectConditionSet(sm.SubjectConditionSet, &scs); err != nil {
		return nil, err
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
		if err = unmarshalAttributeValue(sm.AttributeValue, av); err != nil {
			return nil, err
		}

		a := []*policy.Action{}
		if err = unmarshalActionsProto(sm.Actions, &a); err != nil {
			return nil, err
		}

		scs := policy.SubjectConditionSet{}
		if err = unmarshalSubjectConditionSet(sm.SubjectConditionSet, &scs); err != nil {
			return nil, err
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

// Mutates provided fields and returns the updated subject mapping
func (c PolicyDBClient) UpdateSubjectMapping(ctx context.Context, r *subjectmapping.UpdateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	id := r.GetId()
	subjectConditionSetID := r.GetSubjectConditionSetId()
	actions := r.GetActions()
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetSubjectMapping(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var actionsJSON []byte
	if actions != nil {
		actionsJSON, err = marshalActionsProto(actions)
		if err != nil {
			return nil, err
		}
	}

	count, err := c.Queries.UpdateSubjectMapping(ctx, UpdateSubjectMappingParams{
		ID:                    id,
		Actions:               actionsJSON,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgtypeUUID(subjectConditionSetID),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectMapping{
		Id:       id,
		Actions:  actions,
		Metadata: metadata,
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: subjectConditionSetID,
		},
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

	return subjectMappingHydrateList(rows)
}
