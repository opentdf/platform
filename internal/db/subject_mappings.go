package db

import (
	"context"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"
	"google.golang.org/protobuf/encoding/protojson"
)

var SubjectMappingTable = tableName(TableSubjectMappings)
var SubjectMappingOperatorEnumPrefix = "SUBJECT_MAPPINGS_OPERATOR_ENUM_"

func subjectMappingOperatorEnumTransformIn(value string) string {
	return strings.TrimPrefix(value, SubjectMappingOperatorEnumPrefix)
}

func subjectMappingOperatorEnumTransformOut(value string) subjectmapping.SubjectMappingOperatorEnum {
	return subjectmapping.SubjectMappingOperatorEnum(subjectmapping.SubjectMappingOperatorEnum_value[SubjectMappingsOperatorEnumPrefix+value])
}

func subjectMappingSelect() sq.SelectBuilder {
	return newStatementBuilder().Select(
		tableField(SubjectMappingTable, "id"),
		tableField(SubjectMappingTable, "operator"),
		tableField(SubjectMappingTable, "subject_attribute"),
		tableField(SubjectMappingTable, "subject_attribute_values"),
		tableField(SubjectMappingTable, "metadata"),
		"JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', "+tableField(AttributeValueTable, "id")+", "+
			"'value', "+tableField(AttributeValueTable, "value")+","+
			"'members', "+tableField(AttributeValueTable, "members")+
			")"+
			") AS attribute_value",
	).
		LeftJoin(AttributeValueTable + " ON " + tableField(AttributeValueTable, "id") + " = " + tableField(SubjectMappingTable, "id")).
		GroupBy(tableField(SubjectMappingTable, "id"))
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
		return nil, err
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	v := &attributes.Value{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, v); err != nil {
			return nil, err
		}
	}

	s := &subjectmapping.SubjectMapping{
		Id:               id,
		Operator:         subjectMappingOperatorEnumTransformOut(operator),
		SubjectAttribute: subjectAttribute,
		SubjectValues:    subjectAttributeValues,
		Metadata:         m,
		AttributeValue:   v,
	}
	return s, nil
}

///
/// SubjectMapping CRUD
///

func createSubjectMappingSql(attribute_value_id string, operator string, subject_attribute string, subject_attribute_values []string, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(SubjectMappingTable).
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
func (c *Client) CreateSubjectMapping(ctx context.Context, s *subjectmapping.SubjectMappingCreateUpdate) (*subjectmapping.SubjectMapping, error) {
	metadataJson, metadata, err := marshalCreateMetadata(s.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createSubjectMappingSql(
		s.AttributeValueId,
		subjectMappingOperatorEnumTransformIn(s.Operator.String()),
		s.SubjectAttribute,
		s.SubjectValues,
		metadataJson,
	)

	var id string
	if r, err := c.queryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, err
	}

	// a, err := c.GetAttributeValue(ctx, s.AttributeValueId)

	rS := &subjectmapping.SubjectMapping{
		Id: id,
		// Attribute:     a,
		Operator:         s.Operator,
		SubjectAttribute: s.SubjectAttribute,
		SubjectValues:    s.SubjectValues,
		Metadata:         metadata,
	}
	return rS, nil
}

func getSubjectMappingSql(id string) (string, []interface{}, error) {
	return subjectMappingSelect().
		From(SubjectMappingTable).
		Where(sq.Eq{"id": id}).
		ToSql()
}
func (c *Client) GetSubjectMapping(ctx context.Context, id string) (*subjectmapping.SubjectMapping, error) {
	sql, args, err := getSubjectMappingSql(id)

	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	s, err := subjectMappingHydrateItem(row)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// func (c *Client) ListSubjectMapping(ctx context.Context, descriptor string) ([]byte, error) {
// 	return c.ReadResource(ctx, descriptor)
// }

// func (c *Client) UpdateSubjectMapping(ctx context.Context, descriptor string, resource []byte) error {
// 	return c.UpdateResource(ctx, descriptor, resource)
// }

// func (c *Client) DeleteSubjectMapping(ctx context.Context, descriptor string) error {
// 	return c.DeleteResource(ctx, descriptor)
// }
