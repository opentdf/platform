package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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

///
// CRUD operations
///

func (c PolicyDBClient) ListAttributes(ctx context.Context, state string, namespace string) ([]*policy.Attribute, error) {
	var (
		active = pgtype.Bool{
			Valid: false,
		}
		namespaceID   = ""
		namespaceName = ""
	)

	if state != "" && state != StateAny {
		active = pgtype.Bool{
			Bool:  state == StateActive,
			Valid: true,
		}
	}

	if namespace != "" {
		if _, err := uuid.Parse(namespace); err == nil {
			namespaceID = namespace
		} else {
			namespaceName = namespace
		}
	}

	list, err := c.Queries.ListAttributesDetail(ctx, ListAttributesDetailParams{
		Active:        active,
		NamespaceID:   namespaceID,
		NamespaceName: namespaceName,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	policyAttributes := make([]*policy.Attribute, len(list))

	for i, attr := range list {
		metadata := &common.Metadata{}
		if err := unmarshalMetadata(attr.Metadata, metadata, c.logger); err != nil {
			return nil, err
		}

		var v []*policy.Value
		if attr.Values != nil {
			v, err = attributesValuesProtojson(attr.Values, sql.NullString(attr.Fqn))
			if err != nil {
				c.logger.ErrorContext(ctx, "could not unmarshal values", slog.String("error", err.Error()))
				return nil, err
			}
		}

		ns := &policy.Namespace{
			Id:   attr.NamespaceID,
			Name: attr.NamespaceName.String,
			Fqn:  fmt.Sprintf("https://%s", attr.NamespaceName.String),
		}

		policyAttributes[i] = &policy.Attribute{
			Id:        attr.ID,
			Name:      attr.AttributeName,
			Rule:      attributesRuleTypeEnumTransformOut(string(attr.Rule)),
			Metadata:  metadata,
			Namespace: ns,
			Active:    &wrapperspb.BoolValue{Value: attr.Active},
			Values:    nil,
			Fqn:       attr.Fqn.String,
		}

		// Deactivations of individual values can unsync the order in the values_order column and the selected number of attribute values.
		// In Go, int value 0 is not equal to 0, so check if they're not equal and more than 0 to check a potential count mismatch.
		mismatchedCount := len(v) > 0 && len(attr.ValuesOrder) > 0 && len(attr.ValuesOrder) != len(v)

		// sort the values according to the order
		ordered := make([]*policy.Value, 0)
		for _, order := range attr.ValuesOrder {
			for _, value := range v {
				if value.GetId() == order {
					ordered = append(ordered, value)
					break
				}
				// If all values are active, the order should be correct and the number of values should match the count of ordered ids.
				if mismatchedCount && !value.GetActive().GetValue() {
					c.logger.WarnContext(ctx, "attribute's values order and number of values do not match - DB is in potentially bad state",
						slog.String("attribute definition id", attr.ID),
						slog.Any("expected values order", attr.ValuesOrder),
						slog.Any("retrieved values", v),
					)
				}
			}
		}

		policyAttributes[i].Values = ordered
	}

	return policyAttributes, nil
}

func (c PolicyDBClient) ListAllAttributes(ctx context.Context) ([]*policy.Attribute, error) {
	// call general List method with empty params to get all attributes
	return c.ListAttributes(ctx, "", "")
}

func (c PolicyDBClient) GetAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	attr, err := c.Queries.GetAttribute(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(attr.Metadata, metadata, c.logger); err != nil {
		return nil, err
	}

	var v []*policy.Value
	if attr.Values != nil {
		v, err = attributesValuesProtojson(attr.Values, sql.NullString(attr.Fqn))
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal values", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var k []*policy.KeyAccessServer
	if attr.Grants != nil {
		k, err = db.KeyAccessServerProtoJSON(attr.Grants)
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal key access grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	ns := &policy.Namespace{
		Id:   attr.NamespaceID,
		Name: attr.NamespaceName.String,
		Fqn:  fmt.Sprintf("https://%s", attr.NamespaceName.String),
	}

	policyAttr := &policy.Attribute{
		Id:        id,
		Name:      attr.AttributeName,
		Rule:      attributesRuleTypeEnumTransformOut(string(attr.Rule)),
		Active:    &wrapperspb.BoolValue{Value: attr.Active},
		Metadata:  metadata,
		Namespace: ns,
		Grants:    k,
		Fqn:       attr.Fqn.String,
	}

	// Deactivations of individual values can unsync the order in the values_order column and the selected number of attribute values.
	// In Go, int value 0 is not equal to 0, so check if they're not equal and more than 0 to check a potential count mismatch.
	mismatchedCount := len(v) > 0 && len(attr.ValuesOrder) > 0 && len(attr.ValuesOrder) != len(v)

	// sort the values according to the order
	ordered := make([]*policy.Value, 0)
	for _, order := range attr.ValuesOrder {
		for _, value := range v {
			if value.GetId() == order {
				ordered = append(ordered, value)
				break
			}
			// If all values are active, the order should be correct and the number of values should match the count of ordered ids.
			if mismatchedCount && !value.GetActive().GetValue() {
				c.logger.WarnContext(ctx, "attribute's values order and number of values do not match - DB is in potentially bad state",
					slog.String("attribute definition id", id),
					slog.Any("expected values order", attr.ValuesOrder),
					slog.Any("retrieved values", v),
				)
			}
		}
	}
	policyAttr.Values = ordered

	return policyAttr, nil
}

func (c PolicyDBClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
	fullAttr, err := c.Queries.GetAttributeByDefOrValueFqn(ctx, fqn)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	ns := new(policy.Namespace)
	err = protojson.Unmarshal(fullAttr.Namespace, ns)
	if err != nil {
		c.logger.Error("could not unmarshal namespace", slog.String("error", err.Error()))
		return nil, err
	}

	values, err := attributesValuesProtojson(fullAttr.Values, sql.NullString{Valid: false})
	if err != nil {
		c.logger.Error("could not unmarshal values", slog.String("error", err.Error()))
		return nil, err
	}

	m := new(common.Metadata)
	if fullAttr.Metadata != nil {
		err = unmarshalMetadata(fullAttr.Metadata, m, c.logger)
		if err != nil {
			c.logger.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var grants []*policy.KeyAccessServer
	if fullAttr.DefinitionGrants != nil {
		grants, err = db.KeyAccessServerProtoJSON(fullAttr.DefinitionGrants)
		if err != nil {
			c.logger.Error("could not unmarshal grants", slog.String("error", err.Error()))
			return nil, err
		}
	}
	return &policy.Attribute{
		Id:        fullAttr.ID,
		Name:      fullAttr.Name,
		Rule:      attributesRuleTypeEnumTransformOut(string(fullAttr.Rule)),
		Fqn:       fullAttr.DefinitionFqn,
		Active:    &wrapperspb.BoolValue{Value: fullAttr.Active},
		Grants:    grants,
		Metadata:  m,
		Namespace: ns,
		Values:    values,
	}, nil
}

func (c PolicyDBClient) GetAttributesByNamespace(ctx context.Context, namespaceID string) ([]*policy.Attribute, error) {
	list, err := c.Queries.ListAttributesSummary(ctx, namespaceID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	policyAttributes := make([]*policy.Attribute, len(list))

	for i, attr := range list {
		metadata := &common.Metadata{}
		if err := unmarshalMetadata(attr.Metadata, metadata, c.logger); err != nil {
			return nil, err
		}

		ns := &policy.Namespace{
			Id:   attr.NamespaceID,
			Name: attr.NamespaceName.String,
			Fqn:  fmt.Sprintf("https://%s", attr.NamespaceName.String),
		}

		policyAttributes[i] = &policy.Attribute{
			Id:        attr.ID,
			Name:      attr.AttributeName,
			Rule:      attributesRuleTypeEnumTransformOut(string(attr.Rule)),
			Metadata:  metadata,
			Namespace: ns,
			Active:    &wrapperspb.BoolValue{Value: attr.Active},
		}
	}

	return policyAttributes, nil
}

func (c PolicyDBClient) CreateAttribute(ctx context.Context, r *attributes.CreateAttributeRequest) (*policy.Attribute, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	ruleString := attributesRuleTypeEnumTransformIn(r.GetRule().String())

	attr, err := c.Queries.CreateAttribute(ctx, CreateAttributeParams{
		NamespaceID: r.GetNamespaceId(),
		Name:        r.GetName(),
		Rule:        AttributeDefinitionRule(ruleString),
		Metadata:    metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(attr.Metadata, metadata, c.logger); err != nil {
		return nil, err
	}

	// Add values
	var values []*policy.Value
	for _, v := range r.GetValues() {
		req := &attributes.CreateAttributeValueRequest{
			AttributeId: attr.ID,
			Value:       v,
		}
		value, err := c.CreateAttributeValue(ctx, attr.ID, req)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	// Update the FQNs
	namespaceID := r.GetNamespaceId()
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{
		namespaceID: namespaceID,
		attributeID: attr.ID,
	})
	c.logger.DebugContext(ctx, "upserted fqn with new attribute definition", slog.Any("fqn", fqn))

	for _, v := range values {
		fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{
			namespaceID: namespaceID,
			attributeID: attr.ID,
			valueID:     v.GetId(),
		})
		c.logger.DebugContext(ctx, "upserted fqn with new attribute value on new definition create", slog.Any("fqn", fqn))
	}

	a := &policy.Attribute{
		Id:       attr.ID,
		Name:     attr.Name,
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
	ruleString := ""
	if r.GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED {
		ruleString = attributesRuleTypeEnumTransformIn(r.GetRule().String())
	}

	updatedID, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID: id,
		Name: pgtype.Text{
			String: r.GetName(),
			Valid:  r.GetName() != "",
		},
		Rule: NullAttributeDefinitionRule{
			AttributeDefinitionRule: AttributeDefinitionRule(ruleString),
			Valid:                   ruleString != "",
		},
		ValuesOrder: r.GetValuesOrder(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Upsert all the FQNs with the definition name mutation
	if r.GetName() != "" {
		namespaceID := before.GetNamespace().GetId()
		fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: updatedID})
		c.logger.Debug("upserted attribute fqn with new definition name", slog.Any("fqn", fqn))
		if len(before.GetValues()) > 0 {
			for _, v := range before.GetValues() {
				fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: updatedID, valueID: v.GetId()})
				c.logger.Debug("upserted attribute value fqn with new definition name", slog.Any("fqn", fqn))
			}
		}
	}

	return c.GetAttribute(ctx, updatedID)
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

	updatedID, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID:       id,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.Attribute{
		Id: updatedID,
	}, nil
}

func (c PolicyDBClient) DeactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	updatedID, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID: id,
		Active: pgtype.Bool{
			Bool:  false,
			Valid: true,
		},
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttribute(ctx, updatedID)
}

func (c PolicyDBClient) UnsafeReactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	updatedID, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID: id,
		Active: pgtype.Bool{
			Bool:  true,
			Valid: true,
		},
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttribute(ctx, updatedID)
}

func (c PolicyDBClient) UnsafeDeleteAttribute(ctx context.Context, existing *policy.Attribute, fqn string) (*policy.Attribute, error) {
	if existing == nil {
		return nil, fmt.Errorf("attribute not found: %w", db.ErrNotFound)
	}

	if existing.GetFqn() != fqn {
		return nil, fmt.Errorf("fqn mismatch: %w", db.ErrNotFound)
	}

	id := existing.GetId()

	count, err := c.Queries.DeleteAttribute(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Attribute{
		Id: id,
	}, nil
}

///
/// Key Access Server assignments
///

func (c PolicyDBClient) AssignKeyAccessServerToAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	_, err := c.Queries.AssignKeyAccessServerToAttribute(ctx, AssignKeyAccessServerToAttributeParams{
		AttributeDefinitionID: k.GetAttributeId(),
		KeyAccessServerID:     k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}

func (c PolicyDBClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	count, err := c.Queries.RemoveKeyAccessServerFromAttribute(ctx, RemoveKeyAccessServerFromAttributeParams{
		AttributeDefinitionID: k.GetAttributeId(),
		KeyAccessServerID:     k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return k, nil
}
