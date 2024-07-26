package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var AttributeRuleTypeEnumPrefix = "ATTRIBUTE_RULE_TYPE_ENUM_"

func attributesRuleTypeEnumTransformIn(value string) string {
	return strings.TrimPrefix(value, AttributeRuleTypeEnumPrefix)
}

func attributesRuleTypeEnumTransformOut(value string) policy.AttributeRuleTypeEnum {
	return policy.AttributeRuleTypeEnum(policy.AttributeRuleTypeEnum_value[AttributeRuleTypeEnumPrefix+value])
}

func attributesValuesProtojson(valuesJSON []byte, attrFqn sql.NullString) ([]*policy.Value, error) {
	var (
		raw    []json.RawMessage
		values []*policy.Value
	)

	if err := json.Unmarshal(valuesJSON, &raw); err != nil {
		return nil, err
	}

	for _, r := range raw {
		value := &policy.Value{}
		err := protojson.Unmarshal(r, value)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling a value: %w", err)
		}
		if attrFqn.Valid && value.GetFqn() == "" {
			value.Fqn = fmt.Sprintf("%s/value/%s", attrFqn.String, value.GetValue())
		}
		values = append(values, value)
	}
	return values, nil
}

type attributesSelectOptions struct {
	withAttributeValues bool
	withKeyAccessGrants bool
	// withFqn and withOneValueByFqn are mutually exclusive
	withFqn           bool
	withOneValueByFqn string
	state             string
	namespace         string
}

func attributesSelect(opts attributesSelectOptions) sq.SelectBuilder {
	if opts.withKeyAccessGrants {
		opts.withAttributeValues = true
	}

	t := Tables.Attributes
	nt := Tables.Namespaces
	avt := Tables.AttributeValues
	fqnt := Tables.AttrFqn
	smT := Tables.SubjectMappings
	scsT := Tables.SubjectConditionSet
	akagt := Tables.AttributeKeyAccessGrants
	avkagt := Tables.AttributeValueKeyAccessGrants
	selectFields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("rule"),
		constructMetadata(t.Name(), false),
		t.Field("namespace_id"),
		t.Field("active"),
		nt.Field("name"),
	}

	shouldGetValues := opts.withAttributeValues || opts.withOneValueByFqn != "" || opts.withFqn
	if shouldGetValues {
		valueSelect := "JSON_AGG(" +
			"JSON_BUILD_OBJECT(" +
			"'id', avt.id," +
			"'value', avt.value," +
			"'members', avt.members," +
			"'active', avt.active"

		// include the subject mapping / subject condition set for each value
		if opts.withOneValueByFqn != "" {
			valueSelect += ", 'fqn', val_sm_fqn_join.fqn, " +
				"'subject_mappings', sub_maps_arr, " +
				"'grants', val_grants_arr"
		}
		valueSelect += ")) AS values"
		selectFields = append(selectFields, t.Field("values_order"), valueSelect)
	}
	if opts.withKeyAccessGrants {
		// query the attribute definition KAS grants
		selectFields = append(selectFields,
			"JSONB_AGG("+
				"DISTINCT JSONB_BUILD_OBJECT("+
				"'id',"+Tables.KeyAccessServerRegistry.Field("id")+", "+
				"'uri',"+Tables.KeyAccessServerRegistry.Field("uri")+", "+
				"'public_key',"+Tables.KeyAccessServerRegistry.Field("public_key")+
				")) FILTER (WHERE "+akagt.Field("attribute_definition_id")+" IS NOT NULL) AS grants",
		)
	}
	if opts.withFqn {
		selectFields = append(selectFields, fqnt.Field("fqn"))
	}

	sb := db.NewStatementBuilder().Select(selectFields...).
		LeftJoin(nt.Name() + " ON " + nt.Field("id") + " = " + t.Field("namespace_id"))

	if shouldGetValues {
		subQuery := "(SELECT av.id, av.value, av.active, COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
			"'id', vmv.id, " +
			"'value', vmv.value, " +
			"'active', vmv.active, " +
			"'members', vmv.members || ARRAY[]::UUID[], " +
			"'attribute', JSON_BUILD_OBJECT(" +
			"'id', vmv.attribute_definition_id ))) FILTER (WHERE vmv.id IS NOT NULL ), '[]') AS members, " +
			"JSON_AGG(DISTINCT JSONB_BUILD_OBJECT(" +
			"'id', vkas.id," +
			"'uri', vkas.uri," +
			"'public_key', vkas.public_key " +
			")) FILTER (WHERE vkas.id IS NOT NULL AND vkas.uri IS NOT NULL AND vkas.public_key IS NOT NULL) AS val_grants_arr, " +
			"av.attribute_definition_id FROM " + avt.Name() + " av " +
			"LEFT JOIN " + avkagt.Name() + " avg ON av.id = avg.attribute_value_id " +
			"LEFT JOIN " + Tables.KeyAccessServerRegistry.Name() + " vkas ON avg.key_access_server_id = vkas.id " +
			"LEFT JOIN " + Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id LEFT JOIN " + avt.Name() + " vmv ON vm.member_id = vmv.id "
		if opts.withOneValueByFqn != "" {
			subQuery += "WHERE av.active = true "
		}
		subQuery += "GROUP BY av.id) avt ON avt.attribute_definition_id = " + t.Field("id")
		sb = sb.LeftJoin(subQuery)
	}
	if opts.withKeyAccessGrants {
		sb = sb.
			LeftJoin(akagt.Name() + " ON " + akagt.WithoutSchema().Name() + ".attribute_definition_id = " + t.Field("id")).
			LeftJoin(Tables.KeyAccessServerRegistry.Name() + " ON " + Tables.KeyAccessServerRegistry.Field("id") + " = " + akagt.Field("key_access_server_id"))
	}
	if opts.withFqn {
		sb = sb.LeftJoin(fqnt.Name() + " ON " + fqnt.Field("attribute_id") + " = " + t.Field("id") +
			" AND " + fqnt.Field("value_id") + " IS NULL")
	}

	if opts.withOneValueByFqn != "" {
		sb = sb.LeftJoin(fqnt.Name() + " ON " + fqnt.Field("attribute_id") + " = " + t.Field("id")).
			LeftJoin("(SELECT " +
				avt.Field("id") + " AS av_id," +
				"JSON_AGG(JSON_BUILD_OBJECT(" +
				"'id', " + smT.Field("id") + "," +
				"'actions', " + smT.Field("actions") + "," +
				constructMetadata(smT.Name(), true) +
				"'subject_condition_set', JSON_BUILD_OBJECT(" +
				"'id', " + scsT.Field("id") + "," +
				constructMetadata(scsT.Name(), true) +
				"'subject_sets', " + scsT.Field("condition") +
				")" +
				")) AS sub_maps_arr " +
				", inner_fqns.fqn AS fqn " +
				"FROM " + smT.Name() + " " +
				"LEFT JOIN " + avt.Name() + " ON " + smT.Field("attribute_value_id") + " = " + avt.Field("id") + " " +
				"LEFT JOIN " + scsT.Name() + " ON " + smT.Field("subject_condition_set_id") + " = " + scsT.Field("id") + " " +
				"INNER JOIN " + fqnt.Name() + " AS inner_fqns ON " + avt.Field("id") + " = inner_fqns.value_id " +
				"WHERE inner_fqns.fqn = '" + opts.withOneValueByFqn + "' " +
				"AND " + avt.Field("active") + " = true " +
				"GROUP BY " + avt.Field("id") + ", inner_fqns.fqn " +
				") AS val_sm_fqn_join ON " + "avt.id" + " = val_sm_fqn_join.av_id " +
				"AND " + "avt.id" + " = " + fqnt.Field("value_id"),
			)
	}
	g := []string{t.Field("id"), nt.Field("name")}

	if opts.withFqn {
		g = append(g, fqnt.Field("fqn"))
	}

	return sb.GroupBy(g...)
}

func attributesHydrateItem(row pgx.Row, opts attributesSelectOptions, logger *logger.Logger) (*policy.Attribute, error) {
	if opts.withKeyAccessGrants {
		opts.withAttributeValues = true
	}

	var (
		id            string
		name          string
		rule          string
		metadataJSON  []byte
		namespaceID   string
		active        bool
		namespaceName string
		valuesJSON    []byte
		valuesOrder   []string
		grants        []byte
		fqn           sql.NullString
	)

	fields := []interface{}{&id, &name, &rule, &metadataJSON, &namespaceID, &active, &namespaceName}
	shouldGetValues := opts.withAttributeValues || opts.withOneValueByFqn != "" || opts.withFqn
	if shouldGetValues {
		fields = append(fields, &valuesOrder, &valuesJSON)
	}
	if opts.withKeyAccessGrants {
		fields = append(fields, &grants)
	}
	if opts.withFqn {
		fields = append(fields, &fqn)
	}

	err := row.Scan(fields...)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			logger.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var v []*policy.Value
	if valuesJSON != nil {
		v, err = attributesValuesProtojson(valuesJSON, fqn)
		if err != nil {
			logger.Error("could not unmarshal values", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var k []*policy.KeyAccessServer
	if grants != nil {
		k, err = db.KeyAccessServerProtoJSON(grants)
		if err != nil {
			logger.Error("could not unmarshal key access grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	ns := &policy.Namespace{
		Id:   namespaceID,
		Name: namespaceName,
		Fqn:  fmt.Sprintf("https://%s", namespaceName),
	}

	attr := &policy.Attribute{
		Id:        id,
		Name:      name,
		Rule:      attributesRuleTypeEnumTransformOut(rule),
		Active:    &wrapperspb.BoolValue{Value: active},
		Metadata:  m,
		Namespace: ns,
		Grants:    k,
		Fqn:       fqn.String,
	}

	// Deactivations of individual values can unsync the order in the values_order column and the selected number of attribute values.
	// In Go, int value 0 is not equal to 0, so check if they're not equal and more than 0 to check a potential count mismatch.
	mismatchedCount := len(v) > 0 && len(valuesOrder) > 0 && len(valuesOrder) != len(v)

	// sort the values according to the order
	ordered := make([]*policy.Value, 0)
	for _, order := range valuesOrder {
		for _, value := range v {
			if value.GetId() == order {
				ordered = append(ordered, value)
				break
			}
			// If all values are active, the order should be correct and the number of values should match the count of ordered ids.
			if mismatchedCount && !value.GetActive().GetValue() {
				logger.Warn("attribute's values order and number of values do not match - DB is in potentially bad state", slog.String("attribute definition id", id), slog.Any("expected values order", valuesOrder), slog.Any("retrieved values", v))
			}
		}
	}
	attr.Values = ordered

	return attr, nil
}

func attributesHydrateList(rows pgx.Rows, opts attributesSelectOptions, logger *logger.Logger) ([]*policy.Attribute, error) {
	list := make([]*policy.Attribute, 0)
	for rows.Next() {
		attr, err := attributesHydrateItem(rows, opts, logger)
		if err != nil {
			return nil, err
		}
		list = append(list, attr)
	}
	return list, nil
}

///
// CRUD operations
///

func listAllAttributesSQL(opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := attributesSelect(opts).
		From(t.Name())

	if opts.state != "" && opts.state != StateAny {
		sb = sb.Where(sq.Eq{t.Field("active"): opts.state == StateActive})
	}

	if opts.namespace != "" {
		_, err := uuid.Parse(opts.namespace)
		if err == nil {
			sb = sb.Where(sq.Eq{t.Field("namespace_id"): opts.namespace})
		} else {
			sb = sb.Where(sq.Eq{Tables.Namespaces.Field("name"): opts.namespace})
		}
	}
	return sb.ToSql()
}

func (c PolicyDBClient) ListAllAttributes(ctx context.Context, state string, namespace string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
		namespace:           namespace,
	}

	sql, args, err := listAllAttributesSQL(opts)
	if err != nil {
		return nil, err
	}
	c.logger.Debug("list all attributes", slog.String("sql", sql), slog.Any("args", args))

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts, c.logger)
	if err != nil {
		c.logger.Error("could not hydrate list", slog.String("error", err.Error()))
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return list, nil
}

func (c PolicyDBClient) ListAllAttributesWithout(ctx context.Context, state string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: false,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
	}

	sql, args, err := listAllAttributesSQL(opts)
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts, c.logger)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	c.logger.Debug("list", slog.Any("list", list))

	return list, nil
}

func getAttributeSQL(id string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("id"): id}).
		From(t.Name()).
		ToSql()
}

func (c PolicyDBClient) GetAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withFqn:             true,
		withAttributeValues: true,
		withKeyAccessGrants: true,
	}
	sql, args, err := getAttributeSQL(id, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attribute, err := attributesHydrateItem(row, opts, c.logger)
	if err != nil {
		c.logger.Error("could not hydrate item", slog.String("attributeId", id), slog.String("error", err.Error()))
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return attribute, nil
}

// Get attribute by fqn, ensuring the attribute definition and namespace are both active
func getAttributeByFqnSQL(fqn string, opts attributesSelectOptions) (string, []interface{}, error) {
	return attributesSelect(opts).
		Where(sq.Eq{Tables.AttrFqn.Field("fqn"): fqn, Tables.Attributes.Field("active"): true, Tables.Namespaces.Field("active"): true}).
		From(Tables.Attributes.Name()).
		ToSql()
}

func (c PolicyDBClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
	// normalize to lower case
	fqn = strings.ToLower(fqn)
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: true,
	}
	if strings.Contains(fqn, "/value/") {
		opts.withOneValueByFqn = fqn
	} else {
		opts.withFqn = true
	}
	sql, args, err := getAttributeByFqnSQL(fqn, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attribute, err := attributesHydrateItem(row, opts, c.logger)
	if err != nil {
		c.logger.Error("could not hydrate item", slog.String("fqn", fqn), slog.String("error", err.Error()))
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	return attribute, nil
}

func getAttributesByNamespaceSQL(namespaceID string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("namespace_id"): namespaceID}).
		From(t.Name()).
		ToSql()
}

func (c PolicyDBClient) GetAttributesByNamespace(ctx context.Context, namespaceID string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{}
	sql, args, err := getAttributesByNamespaceSQL(namespaceID, opts)
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts, c.logger)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return list, nil
}

func createAttributeSQL(namespaceID string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("namespace_id", "name", "rule", "metadata").
		Values(namespaceID, name, rule, metadata).
		Suffix(createSuffix).
		ToSql()
}

func (c PolicyDBClient) CreateAttribute(ctx context.Context, r *attributes.CreateAttributeRequest) (*policy.Attribute, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	name := strings.ToLower(r.GetName())

	sql, args, err := createAttributeSQL(r.GetNamespaceId(), name, attributesRuleTypeEnumTransformIn(r.GetRule().String()), metadataJSON)
	if err != nil {
		return nil, err
	}

	var id string
	if r, err := c.QueryRow(ctx, sql, args); err != nil {
		return nil, err
	} else if err := r.Scan(&id, &metadataJSON); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(metadataJSON, metadata, c.logger); err != nil {
		return nil, err
	}

	// Add values
	var values []*policy.Value
	for _, v := range r.GetValues() {
		req := &attributes.CreateAttributeValueRequest{AttributeId: id, Value: v}
		value, err := c.CreateAttributeValue(ctx, id, req)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	// Update the FQNs
	namespaceID := r.GetNamespaceId()
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: id})
	c.logger.Debug("upserted fqn with new attribute definition", slog.Any("fqn", fqn))

	for _, v := range values {
		fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: id, valueID: v.GetId()})
		c.logger.Debug("upserted fqn with new attribute value on new definition create", slog.Any("fqn", fqn))
	}

	a := &policy.Attribute{
		Id:       id,
		Name:     name,
		Rule:     r.GetRule(),
		Metadata: metadata,
		Namespace: &policy.Namespace{
			Id: r.GetNamespaceId(),
		},
		Active: &wrapperspb.BoolValue{Value: true},
		Values: values,
	}
	return a, nil
}

func unsafeUpdateAttributeSQL(id string, updateName string, updateRule string, replaceValuesOrder []string) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := db.NewStatementBuilder().Update(t.Name())

	if updateName != "" {
		sb = sb.Set("name", updateName)
	}
	if updateRule != "" {
		sb = sb.Set("rule", updateRule)
	}
	if len(replaceValuesOrder) > 0 {
		sb = sb.Set("values_order", replaceValuesOrder)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDBClient) UnsafeUpdateAttribute(ctx context.Context, r *unsafe.UnsafeUpdateAttributeRequest) (*policy.Attribute, error) {
	id := r.GetId()
	before, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, err
	}

	// Validate that the values_order contains all the children value id's of this attribute
	lenExistingValues := len(before.GetValues())
	lenNewValues := len(r.GetValuesOrder())
	if lenNewValues > 0 {
		if lenExistingValues != lenNewValues {
			return nil, fmt.Errorf("values_order can only be updated with current attribute values: %w", db.ErrForeignKeyViolation)
		}
		// check if all the children value id's of this attribute are in the values_order
		for _, v := range before.GetValues() {
			found := false
			for _, vo := range r.GetValuesOrder() {
				if v.GetId() == vo {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("values_order can only be updated with current attribute values: %w", db.ErrForeignKeyViolation)
			}
		}
	}

	// Handle case where rule is not actually being updated
	rule := ""
	if r.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED {
		rule = attributesRuleTypeEnumTransformIn(r.GetRule().String())
	}

	sql, args, err := unsafeUpdateAttributeSQL(id, strings.ToLower(r.GetName()), rule, r.GetValuesOrder())
	if err != nil {
		return nil, err
	}

	err = c.Exec(ctx, sql, args)
	if err != nil {
		return nil, err
	}

	// Upsert all the FQNs with the definition name mutation
	if r.GetName() != "" {
		namespaceID := before.GetNamespace().GetId()
		fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: id})
		c.logger.Debug("upserted attribute fqn with new definition name", slog.Any("fqn", fqn))
		if len(before.GetValues()) > 0 {
			for _, v := range before.GetValues() {
				fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: id, valueID: v.GetId()})
				c.logger.Debug("upserted attribute value fqn with new definition name", slog.Any("fqn", fqn))
			}
		}
	}

	return c.GetAttribute(ctx, id)
}

func safeUpdateAttributeSQL(id string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := db.NewStatementBuilder().Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDBClient) UpdateAttribute(ctx context.Context, id string, r *attributes.UpdateAttributeRequest) (*policy.Attribute, error) {
	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetAttribute(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := safeUpdateAttributeSQL(id, metadataJSON)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.Attribute{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.Attribute{
		Id: id,
	}, nil
}

func deactivateAttributeSQL(id string) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDBClient) DeactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	sql, args, err := deactivateAttributeSQL(id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}
	return c.GetAttribute(ctx, id)
}

func unsafeReactivateAttributeSQL(id string) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", true).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDBClient) UnsafeReactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	sql, args, err := unsafeReactivateAttributeSQL(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return c.GetAttribute(ctx, id)
}

func unsafeDeleteAttributeSQL(id string) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDBClient) UnsafeDeleteAttribute(ctx context.Context, existing *policy.Attribute, fqn string) (*policy.Attribute, error) {
	if existing == nil {
		return nil, fmt.Errorf("attribute not found: %w", db.ErrNotFound)
	}
	id := existing.GetId()

	if existing.GetFqn() != fqn {
		return nil, fmt.Errorf("fqn mismatch: %w", db.ErrNotFound)
	}
	sql, args, err := unsafeDeleteAttributeSQL(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.Attribute{
		Id: id,
	}, nil
}

///
/// Key Access Server assignments
///

func assignKeyAccessServerToAttributeSQL(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeKeyAccessGrants
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("attribute_definition_id", "key_access_server_id").
		Values(attributeID, keyAccessServerID).
		ToSql()
}

func (c PolicyDBClient) AssignKeyAccessServerToAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToAttributeSQL(k.GetAttributeId(), k.GetKeyAccessServerId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}

func removeKeyAccessServerFromAttributeSQL(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeKeyAccessGrants
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{"attribute_definition_id": attributeID, "key_access_server_id": keyAccessServerID}).
		Suffix("IS TRUE RETURNING *").
		ToSql()
}

func (c PolicyDBClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromAttributeSQL(k.GetAttributeId(), k.GetKeyAccessServerId())
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}
