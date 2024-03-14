package db

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
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
func unmarshalSubjectSetsProto(conditionJSON []byte) ([]*policy.SubjectSet, error) {
	var (
		raw []json.RawMessage
		ss  []*policy.SubjectSet
	)
	if err := json.Unmarshal(conditionJSON, &raw); err != nil {
		slog.Error("failed to unmarshal subject sets", slog.String("error", err.Error()), slog.String("condition JSON", string(conditionJSON)))
		return nil, err
	}

	for _, r := range raw {
		s := policy.SubjectSet{}
		if err := protojson.Unmarshal(r, &s); err != nil {
			slog.Error("failed to unmarshal subject set", slog.String("error", err.Error()), slog.String("subject set JSON", string(r)))
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

func unmarshalActionsProto(actionsJSON []byte) ([]*policy.Action, error) {
	var (
		raw     []json.RawMessage
		actions []*policy.Action
	)
	if err := json.Unmarshal(actionsJSON, &raw); err != nil {
		slog.Error("failed to unmarshal actions", slog.String("error", err.Error()), slog.String("actions JSON", string(actionsJSON)))
		return nil, err
	}

	for _, r := range raw {
		a := policy.Action{}
		if err := protojson.Unmarshal(r, &a); err != nil {
			slog.Error("failed to unmarshal action", slog.String("error", err.Error()), slog.String("action JSON", string(r)))
			return nil, err
		}
		actions = append(actions, &a)
	}
	return actions, nil
}

func subjectConditionSetSelect() sq.SelectBuilder {
	t := Tables.SubjectConditionSet
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("metadata"),
		t.Field("condition"),
	)
}

func subjectConditionSetHydrateItem(row pgx.Row) (*policy.SubjectConditionSet, error) {
	var (
		id        string
		metadata  []byte
		condition []byte
	)

	err := row.Scan(
		&id,
		&metadata,
		&condition,
	)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadata != nil {
		if err := protojson.Unmarshal(metadata, m); err != nil {
			slog.Error("failed to unmarshal metadata", slog.String("error", err.Error()), slog.String("metadata JSON", string(metadata)))
			return nil, err
		}
	}

	ss, err := unmarshalSubjectSetsProto(condition)
	if err != nil {
		return nil, err
	}

	return &policy.SubjectConditionSet{
		Id:          id,
		SubjectSets: ss,
		Metadata:    m,
	}, nil
}

func subjectConditionSetHydrateList(rows pgx.Rows) ([]*policy.SubjectConditionSet, error) {
	list := make([]*policy.SubjectConditionSet, 0)
	for rows.Next() {
		s, err := subjectConditionSetHydrateItem(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, nil
}

func subjectMappingSelect() sq.SelectBuilder {
	t := Tables.SubjectMappings
	avT := Tables.AttributeValues
	scsT := Tables.SubjectConditionSet
	members := "COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
		"'id', vmv.id, " +
		"'value', vmv.value, " +
		"'active', vmv.active, " +
		"'members', vmv.members || ARRAY[]::UUID[] " +
		")) FILTER (WHERE vmv.id IS NOT NULL ), '[]')"
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("actions"),
		t.Field("metadata"),
		"JSON_BUILD_OBJECT("+
			"'id', "+scsT.Field("id")+", "+
			"'metadata', "+scsT.Field("metadata")+", "+
			"'subject_sets', "+scsT.Field("condition")+
			") AS subject_condition_set",
		"JSON_BUILD_OBJECT("+
			"'id', av.id,"+
			"'value', av.value,"+
			"'members', "+members+","+
			"'active', av.active"+
			") AS attribute_value",
	).
		LeftJoin(avT.Name() + " av ON " + t.Field("attribute_value_id") + " = " + "av.id").
		LeftJoin(Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id").
		LeftJoin(avT.Name() + " vmv ON vm.member_id = vmv.id").
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
	slog.Debug(
		"subjectMappingHydrateItem",
		slog.Any("row", row),
		slog.String("id", id),
		slog.String("actionsJSON", string(actionsJSON)),
		slog.String("metadataJSON", string(metadataJSON)),
		slog.String("scsJSON", string(scsJSON)),
		slog.String("attributeValueJSON", string(attributeValueJSON)),
	)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			slog.Error("failed to unmarshal metadata", slog.String("error", err.Error()), slog.String("metadata JSON", string(metadataJSON)))
			return nil, err
		}
	}

	av := &policy.Value{}
	if attributeValueJSON != nil {
		if err := protojson.Unmarshal(attributeValueJSON, av); err != nil {
			slog.Error("failed to unmarshal attribute value", slog.String("error", err.Error()), slog.String("attribute value JSON", string(attributeValueJSON)))
			return nil, err
		}
	}

	a := []*policy.Action{}
	if actionsJSON != nil {
		if a, err = unmarshalActionsProto(actionsJSON); err != nil {
			slog.Error("could not unmarshal actions", slog.String("error", err.Error()), slog.String("actions JSON", string(actionsJSON)))
			return nil, err
		}
	}

	scs := policy.SubjectConditionSet{}
	if scsJSON != nil {
		if err := protojson.Unmarshal(scsJSON, &scs); err != nil {
			slog.Error("could not unmarshal subject condition set", slog.String("error", err.Error()), slog.String("subject condition set JSON", string(scsJSON)))
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

func createSubjectConditionSetSql(subjectSets []*policy.SubjectSet, metadataJSON []byte) (string, []interface{}, error) {
	t := Tables.SubjectConditionSet
	conditionJSON, err := marshalSubjectSetsProto(subjectSets)
	if err != nil {
		slog.Error("could not marshal subject sets", slog.String("error", err.Error()))
		return "", nil, err
	}

	columns := []string{"condition", "metadata"}
	values := []interface{}{conditionJSON, metadataJSON}
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns(columns...).
		Values(values...).
		Suffix("RETURNING \"id\"").
		ToSql()
}

// Creates a new subject condition set and returns the id of the created
func (c PolicyDbClient) CreateSubjectConditionSet(ctx context.Context, s *subjectmapping.SubjectConditionSetCreate) (*policy.SubjectConditionSet, error) {
	metadataJSON, m, err := db.MarshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createSubjectConditionSetSql(s.SubjectSets, metadataJSON)
	if err != nil {
		return nil, err
	}

	var id string
	r, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	if err = r.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	return &policy.SubjectConditionSet{
		Id:          id,
		SubjectSets: s.SubjectSets,
		Metadata:    m,
	}, nil
}

func getSubjectConditionSetSql(id string) (string, []interface{}, error) {
	t := Tables.SubjectConditionSet
	return subjectConditionSetSelect().
		From(t.Name()).Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDbClient) GetSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	sql, args, err := getSubjectConditionSetSql(id)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	return subjectConditionSetHydrateItem(row)
}

func listSubjectConditionSetsSql() (string, []interface{}, error) {
	t := Tables.SubjectConditionSet
	return subjectConditionSetSelect().
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) ListSubjectConditionSets(ctx context.Context) ([]*policy.SubjectConditionSet, error) {
	sql, args, err := listSubjectConditionSetsSql()
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return subjectConditionSetHydrateList(rows)
}

func updateSubjectConditionSetSql(id string, metadata []byte, condition []byte) (string, []interface{}, error) {
	t := Tables.SubjectConditionSet

	sb := db.NewStatementBuilder().
		Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	if condition != nil {
		sb = sb.Set("condition", condition)
	}
	return sb.
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

// Mutates provided fields and returns id of the updated subject condition set
func (c PolicyDbClient) UpdateSubjectConditionSet(ctx context.Context, r *subjectmapping.UpdateSubjectConditionSetRequest) (*policy.SubjectConditionSet, error) {
	var condition []byte

	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.Metadata, r.MetadataUpdateBehavior, func() (*common.Metadata, error) {
		scs, err := c.GetSubjectConditionSet(ctx, r.Id)
		if err != nil {
			return nil, err
		}
		return scs.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	if r.SubjectSets != nil {
		condition, err = marshalSubjectSetsProto(r.SubjectSets)
		if err != nil {
			slog.Error("failed to marshal subject sets", slog.String("error", err.Error()))
			return nil, err
		}
	}

	sql, args, err := updateSubjectConditionSetSql(
		r.Id,
		metadataJSON,
		condition,
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.SubjectConditionSet{
			Id: r.Id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.SubjectConditionSet{
		Id: r.Id,
	}, nil
}

func deleteSubjectConditionSetSql(id string) (string, []interface{}, error) {
	t := Tables.SubjectConditionSet
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

// Deletes specified subject condition set and returns the id of the deleted
func (c PolicyDbClient) DeleteSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	sql, args, err := deleteSubjectConditionSetSql(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.SubjectConditionSet{
		Id: id,
	}, nil
}

func createSubjectMappingSql(attribute_value_id string, actions []byte, metadata []byte, subject_condition_set_id string) (string, []interface{}, error) {
	t := Tables.SubjectMappings

	columns := []string{
		"attribute_value_id",
		"actions",
		"metadata",
		"subject_condition_set_id",
	}
	values := []interface{}{
		attribute_value_id,
		actions,
		metadata,
		subject_condition_set_id,
	}

	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns(columns...).
		Values(values...).
		Suffix("RETURNING \"id\"").
		ToSql()
}

// Creates a new subject mapping and returns the id of the created. If an existing subject condition set id is provided, it will be used.
// If a new subject condition set is provided, it will be created. The existing subject condition set id takes precedence.
func (c PolicyDbClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.CreateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	var (
		scs *policy.SubjectConditionSet
		err error
	)

	// Prefer existing id over new creation per documented proto behavior.
	if s.ExistingSubjectConditionSetId != "" {
		scs, err = c.GetSubjectConditionSet(ctx, s.ExistingSubjectConditionSetId)
		if err != nil {
			return nil, err
		}
	} else if s.NewSubjectConditionSet != nil {
		// create the new subject condition set
		scs, err = c.CreateSubjectConditionSet(ctx, s.NewSubjectConditionSet)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Join(db.ErrMissingValue, errors.New("either an existing Subject Condition Set ID or a new Subject Condition Set is required when creating a subject mapping"))
	}

	metadataJSON, m, err := db.MarshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}
	if s.Actions == nil {
		return nil, errors.Join(db.ErrMissingValue, errors.New("actions are required when creating a subject mapping"))
	}
	actionsJSON, err := marshalActionsProto(s.Actions)
	if err != nil {
		return nil, err
	}

	// Create the subject mapping
	sql, args, err := createSubjectMappingSql(
		s.AttributeValueId,
		actionsJSON,
		metadataJSON,
		scs.Id,
	)

	var id string
	if r, err := c.QueryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectMapping{
		Id: id,
		AttributeValue: &policy.Value{
			Id: s.AttributeValueId,
		},
		SubjectConditionSet: scs,
		Actions:             s.Actions,
		Metadata:            m,
	}, nil
}

func getSubjectMappingSql(id string) (string, []interface{}, error) {
	t := Tables.SubjectMappings
	return subjectMappingSelect().
		From(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) GetSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	sql, args, err := getSubjectMappingSql(id)

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	return subjectMappingHydrateItem(row)
}

func listSubjectMappingsSql() (string, []interface{}, error) {
	t := Tables.SubjectMappings
	return subjectMappingSelect().
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) ListSubjectMappings(ctx context.Context) ([]*policy.SubjectMapping, error) {
	sql, args, err := listSubjectMappingsSql()
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	subjectMappings, err := subjectMappingHydrateList(rows)
	if err != nil {
		return nil, err
	}

	return subjectMappings, nil
}

func updateSubjectMappingSql(id string, metadataJSON []byte, subject_condition_set_id string, actionsJSON []byte) (string, []interface{}, error) {
	t := Tables.SubjectMappings
	sb := db.NewStatementBuilder().
		Update(t.Name())

	if metadataJSON != nil {
		sb = sb.Set("metadata", metadataJSON)
	}

	if subject_condition_set_id != "" {
		sb = sb.Set("subject_condition_set_id", subject_condition_set_id)
	}

	if actionsJSON != nil {
		sb = sb.Set("actions", actionsJSON)
	}

	return sb.
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

// Mutates provided fields and returns id of the updated subject mapping
func (c PolicyDbClient) UpdateSubjectMapping(ctx context.Context, r *subjectmapping.UpdateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	// if extend we need to merge the metadata
	metadataJson, _, err := db.MarshalUpdateMetadata(r.Metadata, r.MetadataUpdateBehavior, func() (*common.Metadata, error) {
		a, err := c.GetSubjectMapping(ctx, r.Id)
		if err != nil {
			return nil, err
		}
		return a.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	var actionsJSON []byte
	if r.Actions != nil {
		actionsJSON, err = marshalActionsProto(r.Actions)
		if err != nil {
			return nil, err
		}
	}

	sql, args, err := updateSubjectMappingSql(
		r.Id,
		metadataJson,
		r.SubjectConditionSetId,
		actionsJSON,
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.SubjectMapping{
			Id: r.Id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.SubjectMapping{
		Id: r.Id,
	}, nil
}

func deleteSubjectMappingSql(id string) (string, []interface{}, error) {
	t := Tables.SubjectMappings
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

// Deletes specified subject mapping and returns the id of the deleted
func (c PolicyDbClient) DeleteSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	sql, args, err := deleteSubjectMappingSql(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
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
// Without this filtering, if a field was something like 'emailAddress' or 'username', every Subject is probably going to relate to that mapping
// in some way or another. This could theoretically be every attribute in the DB if a policy admin has relied heavily on that field.
//
// NOTE: if you have any issues, set the log level to 'debug' for more comprehensive context.
func selectMatchedSubjectMappingsSql(subjectProperties []*policy.SubjectProperty) (string, []interface{}, error) {
	var err error
	if len(subjectProperties) == 0 {
		err = errors.Join(db.ErrMissingValue, errors.New("one or more subject properties is required"))
		slog.Error("subject property missing required value", slog.Any("properties provided", subjectProperties), slog.String("error", err.Error()))
		return "", nil, err
	}
	where := "("
	for i, sp := range subjectProperties {
		if sp.ExternalField == "" || sp.ExternalValue == "" {
			err = errors.Join(db.ErrMissingValue, errors.New("all subject properties must include defined external field and value"))
			slog.Error("subject property missing required value", slog.Any("properties provided", subjectProperties), slog.String("error", err.Error()))
			return "", nil, err
		}
		if i > 0 {
			where += " OR "
		}

		hasField := "each_condition->>'subject_external_field' = '" + sp.ExternalField + "'"
		hasValue := "(each_condition->>'subject_external_values')::jsonb @> '[\"" + sp.ExternalValue + "\"]'::jsonb"
		hasInOperator := "each_condition->>'operator' = 'SUBJECT_MAPPING_OPERATOR_ENUM_IN'"
		hasNotInOperator := "each_condition->>'operator' = 'SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN'"
		// Parses the json and matches the row if either of the following conditions are met:
		where += "((" + hasField + " AND " + hasValue + " AND " + hasInOperator + ")" +
			" OR " +
			"(" + hasField + " AND NOT " + hasValue + " AND " + hasNotInOperator + "))"
		slog.Debug("current condition filter WHERE clause", slog.String("subject_external_field", sp.ExternalField), slog.String("subject_external_value", sp.ExternalValue), slog.String("where", where))
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
		slog.Error("could not generate SQL for subject entitlements", slog.String("error", err.Error()))
		return "", nil, err
	}
	slog.Debug("checking for existence of any condition in the SubjectSets > ConditionGroups > Conditions that matches the provided subject properties", slog.String("where", whereSubQ))

	return subjectMappingSelect().
		From(smT.Name()).
		Where("EXISTS (" + whereSubQ + ")").
		ToSql()
}

// GetMatchedSubjectMappings liberally returns a list of SubjectMappings based on the provided SubjectProperties. The SubjectMappings are returned
// if there is any single condition found among the structures that matches:
// 1. The external field, external value, and an IN operator
// 2. The external field, _no_ external value, and a NOT_IN operator
//
// Without this filtering, if a field was something like 'emailAddress' or 'username', every Subject is probably going to relate to that mapping
// in some way or another, potentially matching every single attribute in the DB if a policy admin has relied heavily on that field. There is no
// logic applied beyond a single condition within the query to avoid business logic interpreting the supplied conditions beyond the bare minimum
// initial filter.
//
// NOTE: This relationship is sometimes called Entitlements or Subject Entitlements.
// NOTE: if you have any issues, set the log level to 'debug' for more comprehensive context.
func (c PolicyDbClient) GetMatchedSubjectMappings(ctx context.Context, properties []*policy.SubjectProperty) ([]*policy.SubjectMapping, error) {
	sql, args, err := selectMatchedSubjectMappingsSql(properties)
	slog.Debug("generated SQL for subject entitlements", slog.Any("properties", properties), slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args, err)
	slog.Debug("executed SQL for subject entitlements", slog.Any("properties", properties), slog.String("sql", sql), slog.Any("args", args), slog.Any("rows", rows), slog.Any("error", err))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return subjectMappingHydrateList(rows)
}
