package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/authorization"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"google.golang.org/protobuf/encoding/protojson"
)

// Helper to marshal SubjectSets into JSON (stored as JSONB in the database column)
func marshalSubjectSetsProto(subjectSet []*subjectmapping.SubjectSet) ([]byte, error) {
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
func unmarshalSubjectSetsProto(conditionJSON []byte) ([]*subjectmapping.SubjectSet, error) {
	var (
		raw []json.RawMessage
		ss  []*subjectmapping.SubjectSet
	)
	if err := json.Unmarshal(conditionJSON, &raw); err != nil {
		return nil, err
	}

	for _, r := range raw {
		s := subjectmapping.SubjectSet{}
		if err := protojson.Unmarshal(r, &s); err != nil {
			return nil, err
		}
		ss = append(ss, &s)
	}

	return ss, nil
}

// Helper to marshal Actions into JSON (stored as JSONB in the database column)
func marshalActionsProto(actions []*authorization.Action) ([]byte, error) {
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

func unmarshalActionsProto(actionsJSON []byte) ([]*authorization.Action, error) {
	var (
		raw     []json.RawMessage
		actions []*authorization.Action
	)
	if err := json.Unmarshal(actionsJSON, &raw); err != nil {
		return nil, err
	}

	for _, r := range raw {
		a := authorization.Action{}
		if err := protojson.Unmarshal(r, &a); err != nil {
			return nil, err
		}
		actions = append(actions, &a)
	}
	return actions, nil
}

func subjectConditionSetSelect() sq.SelectBuilder {
	t := db.Tables.SubjectConditionSet
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("name"),
		t.Field("metadata"),
		t.Field("condition"),
	)
}

func subjectConditionSetHydrateItem(row pgx.Row) (*subjectmapping.SubjectConditionSet, error) {
	var (
		id        string
		name      sql.NullString
		metadata  []byte
		condition []byte
	)

	err := row.Scan(
		&id,
		&name,
		&metadata,
		&condition,
	)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// TODO: do we actually need this check here? Add an integration test for it.
	if condition == nil {
		return nil, errors.Join(db.ErrNotNullViolation, fmt.Errorf("condition not found for subject condition set %s", id))
	}
	m := &common.Metadata{}
	if metadata != nil {
		if err := protojson.Unmarshal(metadata, m); err != nil {
			return nil, err
		}
	}

	ss, err := unmarshalSubjectSetsProto(condition)
	if err != nil {
		return nil, err
	}

	return &subjectmapping.SubjectConditionSet{
		Id:          id,
		Name:        name.String,
		SubjectSets: ss,
		Metadata:    m,
	}, nil
}

func subjectConditionSetHydrateList(rows pgx.Rows) ([]*subjectmapping.SubjectConditionSet, error) {
	list := make([]*subjectmapping.SubjectConditionSet, 0)
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
	t := db.Tables.SubjectMappings
	avT := db.Tables.AttributeValues
	scsT := db.Tables.SubjectConditionSet

	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("actions"),
		t.Field("metadata"),
		"JSON_BUILD_OBJECT("+
			"'id', "+scsT.Field("id")+", "+
			"'name', "+scsT.Field("name")+", "+
			"'metadata', "+scsT.Field("metadata")+", "+
			"'subject_sets', "+scsT.Field("condition")+
			") AS subject_condition_set",
		// TODO: verify we don't need more info about the attribute value here on the JOIN here
		"JSON_BUILD_OBJECT("+
			"'id', "+avT.Field("id")+", "+
			"'value', "+avT.Field("value")+", "+
			"'members', "+avT.Field("members")+
			") AS attribute_value",
	).
		LeftJoin(avT.Name() + " ON " + t.Field("attribute_value_id") + " = " + avT.Field("id")).
		GroupBy(t.Field("id")).
		GroupBy(avT.Field("id")).
		LeftJoin(scsT.Name() + " ON " + scsT.Field("id") + " = " + t.Field("subject_condition_set_id")).
		GroupBy(scsT.Field("id"))
}

func subjectMappingHydrateItem(row pgx.Row) (*subjectmapping.SubjectMapping, error) {
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
			slog.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return nil, err
		}
	}

	av := attributes.Value{}
	if attributeValueJSON != nil {
		if err := protojson.Unmarshal(attributeValueJSON, &av); err != nil {
			slog.Error("could not unmarshal attribute value", slog.String("error", err.Error()))
			return nil, err
		}
	}

	a := []*authorization.Action{}
	if actionsJSON != nil {
		if a, err = unmarshalActionsProto(actionsJSON); err != nil {
			slog.Error("could not unmarshal actions", slog.String("error", err.Error()))
			return nil, err
		}
	}

	scs := subjectmapping.SubjectConditionSet{}
	if scsJSON != nil {
		if err := protojson.Unmarshal(scsJSON, &scs); err != nil {
			slog.Error("could not unmarshal subject condition set", slog.String("error", err.Error()))
			return nil, err
		}
	}

	return &subjectmapping.SubjectMapping{
		Id:                  id,
		Metadata:            m,
		AttributeValue:      &av,
		SubjectConditionSet: &scs,
		Actions:             a,
	}, nil
}

func subjectMappingHydrateList(rows pgx.Rows) ([]*subjectmapping.SubjectMapping, error) {
	list := make([]*subjectmapping.SubjectMapping, 0)
	for rows.Next() {
		s, err := subjectMappingHydrateItem(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, nil
}

func createSubjectConditionSetSql(subjectSets []*subjectmapping.SubjectSet, metadataJSON []byte, name string) (string, []interface{}, error) {
	t := db.Tables.SubjectConditionSet
	conditionJSON, err := marshalSubjectSetsProto(subjectSets)
	if err != nil {
		return "", nil, err
	}

	columns := []string{"condition", "metadata"}
	values := []interface{}{conditionJSON, metadataJSON}
	if name != "" {
		columns = append(columns, "name")
		values = append(values, name)
	}
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns(columns...).
		Values(values...).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) CreateSubjectConditionSet(ctx context.Context, s *subjectmapping.SubjectConditionSetCreate) (*subjectmapping.SubjectConditionSet, error) {
	metadataJSON, m, err := db.MarshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}
	new := &subjectmapping.SubjectConditionSet{
		Name:        s.Name,
		SubjectSets: s.SubjectSets,
		Metadata:    m,
	}

	sql, args, err := createSubjectConditionSetSql(s.SubjectSets, metadataJSON, s.Name)
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
	new.Id = id
	return new, nil
}

func getSubjectConditionSetSql(id string, name string) (string, []interface{}, error) {
	t := db.Tables.SubjectConditionSet
	sb := subjectConditionSetSelect().
		From(t.Name())

	if id != "" {
		return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
	}
	if name != "" {
		return sb.Where(sq.Eq{t.Field("name"): name}).ToSql()
	}
	return "", nil, errors.Join(db.ErrMissingRequiredValue, errors.New("error: Subject Condition Set id or name must be provided"))
}

func (c PolicyDbClient) GetSubjectConditionSet(ctx context.Context, id string, name string) (*subjectmapping.SubjectConditionSet, error) {
	sql, args, err := getSubjectConditionSetSql(id, name)
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
	t := db.Tables.SubjectConditionSet
	return subjectConditionSetSelect().
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) ListSubjectConditionSets(ctx context.Context) ([]*subjectmapping.SubjectConditionSet, error) {
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

func updateSubjectConditionSetSql(id string, name string, metadata []byte, condition []byte) (string, []interface{}, error) {
	t := db.Tables.SubjectConditionSet

	sb := db.NewStatementBuilder().
		Update(t.Name())

	if name != "" {
		sb = sb.Set("name", name)
	}

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

func (c PolicyDbClient) UpdateSubjectConditionSet(ctx context.Context, s *subjectmapping.UpdateSubjectConditionSetRequest) (*subjectmapping.SubjectConditionSet, error) {
	var (
		subjectSets []*subjectmapping.SubjectSet
		condition   []byte
		name        string
	)

	// While an SCS can be retrieved by 'name', an 'id' is required to update one
	prev, err := c.GetSubjectConditionSet(ctx, s.Id, "")
	if err != nil {
		return nil, err
	}

	metadataJSON, metadata, err := db.MarshalUpdateMetadata(prev.Metadata, s.UpdateMetadata)
	if err != nil {
		return nil, err
	}

	if s.UpdateSubjectSets != nil {
		subjectSets = s.UpdateSubjectSets
		condition, err = marshalSubjectSetsProto(subjectSets)
		if err != nil {
			return nil, err
		}
	} else {
		subjectSets = prev.SubjectSets
	}

	if s.UpdateName != "" {
		name = s.UpdateName
	} else {
		name = prev.Name
	}

	sql, args, err := updateSubjectConditionSetSql(
		s.Id,
		name,
		metadataJSON,
		condition,
	)

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return &subjectmapping.SubjectConditionSet{
		Id:          s.Id,
		Name:        name,
		Metadata:    metadata,
		SubjectSets: subjectSets,
	}, nil
}

func deleteSubjectConditionSetSql(id string) (string, []interface{}, error) {
	t := db.Tables.SubjectConditionSet
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) DeleteSubjectConditionSet(ctx context.Context, id string) (*subjectmapping.SubjectConditionSet, error) {
	prev, err := c.GetSubjectConditionSet(ctx, id, "")
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteSubjectConditionSetSql(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}

func createSubjectMappingSql(attribute_value_id string, actions []byte, metadata []byte, subject_condition_set_id string) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings

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

func (c PolicyDbClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.CreateSubjectMappingRequest) (*subjectmapping.SubjectMapping, error) {
	var (
		scs *subjectmapping.SubjectConditionSet
		err error
	)

	// Prefer existing id over new creation per documented proto behavior.
	if s.ExistingSubjectConditionSetId != "" {
		// get the existing subject condition set
		scs, err = c.GetSubjectConditionSet(ctx, s.ExistingSubjectConditionSetId, "")
		if err != nil {
			return nil, err
		}
	} else if s.NewSubjectConditionSet != nil {
		// create the new subject condition sets
		scs, err = c.CreateSubjectConditionSet(ctx, s.NewSubjectConditionSet)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.Join(db.ErrMissingRequiredValue, errors.New("either an existing Subject Condition Set ID or a new one is required when creating a subject mapping"))
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}
	if s.Actions == nil {
		return nil, errors.Join(db.ErrMissingRequiredValue, errors.New("actions are required when creating a subject mapping"))
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

	av, err := c.GetAttributeValue(ctx, s.AttributeValueId)
	if err != nil {
		return nil, err
	}

	sm := &subjectmapping.SubjectMapping{
		Id:                  id,
		Metadata:            metadata,
		AttributeValue:      av,
		SubjectConditionSet: scs,
		Actions:             s.Actions,
	}
	return sm, nil
}

func getSubjectMappingSql(id string) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
	return subjectMappingSelect().
		From(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) GetSubjectMapping(ctx context.Context, id string) (*subjectmapping.SubjectMapping, error) {
	sql, args, err := getSubjectMappingSql(id)

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	return subjectMappingHydrateItem(row)
}

func listSubjectMappingsSql() (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
	return subjectMappingSelect().
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) ListSubjectMappings(ctx context.Context) ([]*subjectmapping.SubjectMapping, error) {
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

// overwrites entire 'actions' JSONB column if updated
func updateSubjectMappingSql(id string, metadataJSON []byte, subject_condition_set_id string, actionsJSON []byte) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
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

func (c PolicyDbClient) UpdateSubjectMapping(ctx context.Context, r *subjectmapping.UpdateSubjectMappingRequest) (*subjectmapping.SubjectMapping, error) {
	prev, err := c.GetSubjectMapping(ctx, r.Id)
	if err != nil {
		return nil, err
	}

	metadataJson, m, err := db.MarshalUpdateMetadata(prev.Metadata, r.UpdateMetadata)
	if err != nil {
		return nil, err
	}
	prev.Metadata = m

	var actionsJSON []byte
	if r.UpdateActions != nil {
		actionsJSON, err = marshalActionsProto(r.UpdateActions)
		if err != nil {
			return nil, err
		}
		prev.Actions = r.UpdateActions
	}

	if r.UpdateSubjectConditionSetId != "" {
		new, err := c.GetSubjectConditionSet(ctx, r.UpdateSubjectConditionSetId, "")
		if err != nil {
			return nil, err
		}
		prev.SubjectConditionSet = new
	}

	sql, args, err := updateSubjectMappingSql(
		r.Id,
		metadataJson,
		r.UpdateSubjectConditionSetId,
		actionsJSON,
	)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}

func deleteSubjectMappingSql(id string) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) DeleteSubjectMapping(ctx context.Context, id string) (*subjectmapping.SubjectMapping, error) {
	prev, err := c.GetSubjectMapping(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteSubjectMappingSql(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}
