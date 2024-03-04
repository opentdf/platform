package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/authorization"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"google.golang.org/protobuf/encoding/protojson"
)

func MarshalSubjectSetsIntoCondition(subjectSet []*subjectmapping.SubjectSet) ([]byte, error) {
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

func UnmarshalSubjectSetsFromCondition(condition []byte) ([]*subjectmapping.SubjectSet, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(condition, &raw); err != nil {
		return nil, err
	}

	var subjectSets []*subjectmapping.SubjectSet
	for _, r := range raw {
		var ss subjectmapping.SubjectSet
		if err := protojson.Unmarshal(r, &ss); err != nil {
			return nil, err
		}
		subjectSets = append(subjectSets, &ss)
	}
	return subjectSets, nil
}

func MarshalActionsProto(actions []*authorization.Action) ([]byte, error) {
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

func UnmarshalActionsProto(actions []byte) ([]*authorization.Action, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(actions, &raw); err != nil {
		return nil, err
	}

	var actionsProto []*authorization.Action
	for _, r := range raw {
		var a authorization.Action
		if err := protojson.Unmarshal(r, &a); err != nil {
			return nil, err
		}
		actionsProto = append(actionsProto, &a)
	}
	return actionsProto, nil
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
		name      string
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

	ss, err := UnmarshalSubjectSetsFromCondition(condition)
	if err != nil {
		return nil, err
	}

	return &subjectmapping.SubjectConditionSet{
		Id:          id,
		Name:        name,
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
	aT := db.Tables.AttributeValues
	ssT := db.Tables.SubjectConditionSet

	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("actions"),
		t.Field("metadata"),
		ssT.Field("condition"),
		"JSON_BUILD_OBJECT("+
			"'id', "+aT.Field("id")+", "+
			"'value', "+aT.Field("value")+", "+
			"'members', "+aT.Field("members")+
			") AS attribute_value",
	).
		LeftJoin(aT.Name() + " ON " + t.Field("attribute_value_id") + " = " + aT.Field("id")).
		LeftJoin(ssT.Name() + " ON " + ssT.Field("id") + " = " + t.Field("subject_condition_set_id")).
		GroupBy(t.Field("id")).
		GroupBy(aT.Field("id"))
}

func subjectMappingHydrateItem(row pgx.Row) (*subjectmapping.SubjectMapping, error) {
	var (
		id                  string
		actions             []byte
		metadataJson        []byte
		smConditionSetsJson []byte
		attributeValueJson  []byte
	)

	err := row.Scan(
		&id,
		&actions,
		&metadataJson,
		&smConditionSetsJson,
		&attributeValueJson,
	)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	v := &attributes.Value{}
	if attributeValueJson != nil {
		if err := protojson.Unmarshal(attributeValueJson, v); err != nil {
			return nil, err
		}
	}

	a, err := UnmarshalActionsProto(actions)
	if err != nil {
		return nil, err
	}

	s := &subjectmapping.SubjectMapping{
		Id:             id,
		Metadata:       m,
		AttributeValue: v,
		// FIXME
		SubjectConditionSet: &subjectmapping.SubjectConditionSet{},
		Actions:             a,
	}
	// FIXME
	// add operator
	s.Actions = append(s.Actions, &authorization.Action{})
	// add subjectAttributeValues
	// s.SubjectSets = append(s.SubjectSets, &subjectmapping.SubjectSet{
	// 	ConditionGroups: make([]*subjectmapping.ConditionGroup, 0),
	// })

	return s, nil
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

func createSubjectConditionSetSql(subSets []*subjectmapping.SubjectSet, metadataJSON []byte, name string) (string, []interface{}, error) {
	t := db.Tables.SubjectConditionSet
	conditionJSON, err := MarshalSubjectSetsIntoCondition(subSets)
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
		sb = sb.Where(sq.Eq{t.Field("id"): id})
	}
	if name != "" {
		sb = sb.Where(sq.Eq{t.Field("name"): name})
	}
	return sb.
		ToSql()
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
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c PolicyDbClient) UpdateSubjectConditionSet(ctx context.Context, id string, s *subjectmapping.SubjectConditionSetUpdate) (*subjectmapping.SubjectConditionSet, error) {
	var (
		prev         *subjectmapping.SubjectConditionSet
		err          error
		metadataJSON []byte
		subjectSets  []*subjectmapping.SubjectSet
		condition    []byte
	)

	prev, err = c.GetSubjectConditionSet(ctx, id, "")
	if err != nil {
		return nil, err
	}

	metadataJSON, metadata, err := db.MarshalUpdateMetadata(prev.Metadata, s.UpdatedMetadata)
	if err != nil {
		return nil, err
	}

	if s.UpdatedSubjectSets != nil {
		subjectSets = s.UpdatedSubjectSets
		condition, err = MarshalSubjectSetsIntoCondition(subjectSets)
		if err != nil {
			return nil, err
		}
	}

	sql, args, err := updateSubjectConditionSetSql(
		id,
		s.UpdatedName,
		metadataJSON,
		condition,
	)

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return &subjectmapping.SubjectConditionSet{
		Id:          id,
		Name:        s.UpdatedName,
		SubjectSets: subjectSets,
		Metadata:    metadata,
	}, nil
}

func deleteSubjectConditionSetSql(id string) (string, []interface{}, error) {
	t := db.Tables.SubjectConditionSet
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{"id": id}).
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

func (c PolicyDbClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.SubjectMappingCreate) (*subjectmapping.SubjectMapping, error) {
	var (
		scs          *subjectmapping.SubjectConditionSet
		err          error
		actionsJSON  []byte
		metadataJSON []byte
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
		return nil, fmt.Errorf("no subject condition set provided")
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}
	actionsJSON, err = MarshalActionsProto(s.Actions)
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

	a, err := c.GetAttributeValue(ctx, s.AttributeValueId)
	if err != nil {
		return nil, err
	}

	sm := &subjectmapping.SubjectMapping{
		Id:                  id,
		Metadata:            metadata,
		AttributeValue:      a,
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

	s, err := subjectMappingHydrateItem(row)
	if err != nil {
		return nil, err
	}

	return s, nil
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

func updateSubjectMappingSql(id string, metadata []byte, subject_condition_set_id string, actions []byte) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
	sb := db.NewStatementBuilder().
		Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	if subject_condition_set_id != "" {
		sb = sb.Set("subject_condition_set_id", subject_condition_set_id)
	}

	if actions != nil {
		sb = sb.Set("actions", actions)
	}

	return sb.
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c PolicyDbClient) UpdateSubjectMapping(ctx context.Context, id string, s *subjectmapping.SubjectMappingUpdate) (*subjectmapping.SubjectMapping, error) {
	prev, err := c.GetSubjectMapping(ctx, id)
	if err != nil {
		return nil, err
	}

	metadataJson, m, err := db.MarshalUpdateMetadata(prev.Metadata, s.UpdateMetadata)
	if err != nil {
		return nil, err
	}
	prev.Metadata = m

	var actionsJSON []byte
	if s.UpdateActions != nil {
		actionsJSON, err = MarshalActionsProto(s.UpdateActions)
		if err != nil {
			return nil, err
		}
	}

	sql, args, err := updateSubjectMappingSql(
		id,
		metadataJson,
		s.UpdateSubjectConditionSetId,
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
		Where(sq.Eq{"id": id}).
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
