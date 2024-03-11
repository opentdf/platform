package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"google.golang.org/protobuf/encoding/protojson"
)

func subjectMappingSelect() sq.SelectBuilder {
	t := db.Tables.SubjectMappings
	aT := db.Tables.AttributeValues
	return db.NewStatementBuilder().Select(
		t.Field("id"),
		t.Field("operator"),
		t.Field("subject_attribute"),
		t.Field("subject_attribute_values"),
		t.Field("metadata"),
		"JSON_BUILD_OBJECT("+
			"'id', "+aT.Field("id")+", "+
			"'value', "+aT.Field("value")+","+
			"'members', "+aT.Field("members")+
			") AS attribute_value",
	).
		LeftJoin(aT.Name() + " ON " + t.Field("id") + " = " + t.Field("id")).
		GroupBy(t.Field("id")).
		GroupBy(aT.Field("id"))
}

func subjectMappingHydrateItem(row pgx.Row) (*subjectmapping.SubjectMapping, error) {
	var (
		id                     string
		operator               string
		subjectAttribute       string
		subjectAttributeValues []string
		metadataJson           []byte
		attributeValueJson     []byte
	)

	err := row.Scan(
		&id,
		&operator,
		&subjectAttribute,
		&subjectAttributeValues,
		&metadataJson,
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

	s := &subjectmapping.SubjectMapping{
		Id:             id,
		Metadata:       m,
		AttributeValue: v,
		SubjectSets:    make([]*subjectmapping.SubjectSet, 0),
		Actions:        make([]*authorization.Action, 0),
	}
	// FIXME
	// add operator
	s.Actions = append(s.Actions, &authorization.Action{})
	// add subjectAttributeValues
	s.SubjectSets = append(s.SubjectSets, &subjectmapping.SubjectSet{
		ConditionGroups: make([]*subjectmapping.ConditionGroup, 0),
	})

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

///
/// SubjectMapping CRUD
///

func createSubjectMappingSql(attribute_value_id string, operator string, subject_attribute string, subject_attribute_values []string, metadata []byte) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns(
			"attribute_value_id",
			"operator",
			"subject_attribute",
			"subject_attribute_values",
			"metadata",
		).
		Values(
			attribute_value_id,
			operator,
			subject_attribute,
			subject_attribute_values,
			metadata,
		).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.SubjectMappingCreateUpdate) (*subjectmapping.SubjectMapping, error) {
	metadataJson, metadata, err := db.MarshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}
	// FIXME
	sql, args, err := createSubjectMappingSql(
		s.AttributeValueId,
		"subjectMappingOperatorEnumTransformIn(s.Operator.String())",
		"s.SubjectAttribute",
		[]string{"s.SubjectValues"},
		metadataJson,
	)

	var id string
	if r, err := c.QueryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// a, err := c.GetAttributeValue(ctx, s.AttributeValueId)

	rS := &subjectmapping.SubjectMapping{
		Id:             id,
		Metadata:       metadata,
		AttributeValue: nil,
		SubjectSets:    nil,
		Actions:        nil,
	}
	return rS, nil
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

func updateSubjectMappingSql(id string, attribute_value_id string, operator string, subject_attribute string, subject_attribute_values []string, metadata []byte) (string, []interface{}, error) {
	t := db.Tables.SubjectMappings
	sb := db.NewStatementBuilder().
		Update(t.Name())

	if attribute_value_id != "" {
		sb.Set("attribute_value_id", attribute_value_id)
	}
	if operator != "" {
		sb.Set("operator", operator)
	}
	if subject_attribute != "" {
		sb.Set("subject_attribute", subject_attribute)
	}
	if subject_attribute_values != nil {
		sb.Set("subject_attribute_values", subject_attribute_values)
	}
	if metadata != nil {
		sb.Set("metadata", metadata)
	}

	return sb.
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c PolicyDbClient) UpdateSubjectMapping(ctx context.Context, id string, s *subjectmapping.SubjectMappingCreateUpdate) (*subjectmapping.SubjectMapping, error) {
	// if extend we need to merge the metadata
	metadataJson, _, err := db.MarshalUpdateMetadata(s.Metadata, common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND, func() (*common.Metadata, error) {
		a, err := c.GetSubjectMapping(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateSubjectMappingSql(
		id,
		s.AttributeValueId,
		"subjectMappingOperatorEnumTransformIn(s.Operator.String())",
		"s.SubjectAttribute",
		[]string{"s.SubjectValues"},
		metadataJson,
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &subjectmapping.SubjectMapping{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &subjectmapping.SubjectMapping{
		Id: id,
	}, nil
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

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return prev, nil
}
