package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
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

func attributesValuesProtojson(valuesJSON []byte) ([]*policy.Value, error) {
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
		values = append(values, value)
	}
	return values, nil
}

type attributeQueryRow struct {
	id            string
	name          string
	rule          string
	metadataJSON  []byte
	namespaceID   string
	active        bool
	namespaceName string
	valuesJSON    []byte
	grantsJSON    []byte
	fqn           sql.NullString
}

func hydrateAttribute(row *attributeQueryRow) (*policy.Attribute, error) {
	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.metadataJSON, metadata); err != nil {
		return nil, err
	}

	var values []*policy.Value
	if row.valuesJSON != nil {
		v, err := attributesValuesProtojson(row.valuesJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal valuesJSON [%s]: %w", string(row.valuesJSON), err)
		}
		values = v
	}

	var grants []*policy.KeyAccessServer
	if row.grantsJSON != nil {
		k, err := db.KeyAccessServerProtoJSON(row.grantsJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal grantsJSON [%s]: %w", string(row.grantsJSON), err)
		}
		grants = k
	}

	ns := &policy.Namespace{
		Id:   row.namespaceID,
		Name: row.namespaceName,
		Fqn:  fmt.Sprintf("https://%s", row.namespaceName),
	}

	attr := &policy.Attribute{
		Id:        row.id,
		Name:      row.name,
		Rule:      attributesRuleTypeEnumTransformOut(row.rule),
		Values:    values,
		Active:    &wrapperspb.BoolValue{Value: row.active},
		Metadata:  metadata,
		Namespace: ns,
		Grants:    grants,
		Fqn:       row.fqn.String,
	}

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
		active = pgtypeBool(state == StateActive)
	}

	if namespace != "" {
		if _, err := uuid.Parse(namespace); err == nil {
			namespaceID = namespace
		} else {
			namespaceName = strings.ToLower(namespace)
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
		policyAttributes[i], err = hydrateAttribute(&attributeQueryRow{
			id:            attr.ID,
			name:          attr.AttributeName,
			rule:          string(attr.Rule),
			active:        attr.Active,
			metadataJSON:  attr.Metadata,
			namespaceID:   attr.NamespaceID,
			namespaceName: attr.NamespaceName.String,
			valuesJSON:    attr.Values,
			fqn:           sql.NullString(attr.Fqn),
		})
		if err != nil {
			return nil, err
		}
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

	policyAttr, err := hydrateAttribute(&attributeQueryRow{
		id:            attr.ID,
		name:          attr.AttributeName,
		rule:          string(attr.Rule),
		active:        attr.Active,
		metadataJSON:  attr.Metadata,
		namespaceID:   attr.NamespaceID,
		namespaceName: attr.NamespaceName.String,
		valuesJSON:    attr.Values,
		grantsJSON:    attr.Grants,
		fqn:           sql.NullString(attr.Fqn),
	})
	if err != nil {
		return nil, err
	}

	return policyAttr, nil
}

func (c PolicyDBClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
	fullAttr, err := c.Queries.GetAttributeByDefOrValueFqn(ctx, strings.ToLower(fqn))
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	ns := new(policy.Namespace)
	err = protojson.Unmarshal(fullAttr.Namespace, ns)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal namespace [%s]: %w", string(fullAttr.Namespace), err)
	}

	values, err := attributesValuesProtojson(fullAttr.Values)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal values [%s]: %w", string(fullAttr.Values), err)
	}

	m := new(common.Metadata)
	if fullAttr.Metadata != nil {
		err = unmarshalMetadata(fullAttr.Metadata, m)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata [%s]: %w", string(fullAttr.Metadata), err)
		}
	}
	var grants []*policy.KeyAccessServer
	if fullAttr.DefinitionGrants != nil {
		grants, err = db.KeyAccessServerProtoJSON(fullAttr.DefinitionGrants)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal grants [%s]: %w", string(fullAttr.DefinitionGrants), err)
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
		policyAttributes[i], err = hydrateAttribute(&attributeQueryRow{
			id:            attr.ID,
			name:          attr.AttributeName,
			rule:          string(attr.Rule),
			active:        attr.Active,
			metadataJSON:  attr.Metadata,
			namespaceID:   attr.NamespaceID,
			namespaceName: attr.NamespaceName.String,
		})
		if err != nil {
			return nil, err
		}
	}

	return policyAttributes, nil
}

func (c PolicyDBClient) CreateAttribute(ctx context.Context, r *attributes.CreateAttributeRequest) (*policy.Attribute, error) {
	name := strings.ToLower(r.GetName())
	namespaceID := r.GetNamespaceId()
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	ruleString := attributesRuleTypeEnumTransformIn(r.GetRule().String())

	createdID, err := c.Queries.CreateAttribute(ctx, CreateAttributeParams{
		NamespaceID: namespaceID,
		Name:        name,
		Rule:        AttributeDefinitionRule(ruleString),
		Metadata:    metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Add values
	var values []*policy.Value
	for _, v := range r.GetValues() {
		req := &attributes.CreateAttributeValueRequest{
			AttributeId: createdID,
			Value:       v,
		}
		value, err := c.CreateAttributeValue(ctx, createdID, req)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	// Update the FQNs
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{
		namespaceID: namespaceID,
		attributeID: createdID,
	})
	c.logger.DebugContext(ctx, "upserted fqn with new attribute definition", slog.Any("fqn", fqn))

	for _, v := range values {
		fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{
			namespaceID: namespaceID,
			attributeID: createdID,
			valueID:     v.GetId(),
		})
		c.logger.DebugContext(ctx, "upserted fqn with new attribute value on new definition create", slog.Any("fqn", fqn))
	}

	a := &policy.Attribute{
		Id:       createdID,
		Name:     name,
		Rule:     r.GetRule(),
		Metadata: metadata,
		Namespace: &policy.Namespace{
			Id: namespaceID,
		},
		Active: &wrapperspb.BoolValue{Value: true},
		Values: values,
		Fqn:    fqn,
	}
	return a, nil
}

func (c PolicyDBClient) UnsafeUpdateAttribute(ctx context.Context, r *unsafe.UnsafeUpdateAttributeRequest) (*policy.Attribute, error) {
	id := r.GetId()
	name := strings.ToLower(r.GetName())
	rule := r.GetRule()
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
	if rule != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED {
		ruleString = attributesRuleTypeEnumTransformIn(rule.String())
	}

	count, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID:   id,
		Name: pgtypeText(name),
		Rule: NullAttributeDefinitionRule{
			AttributeDefinitionRule: AttributeDefinitionRule(ruleString),
			Valid:                   ruleString != "",
		},
		ValuesOrder: r.GetValuesOrder(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	attribute := &policy.Attribute{
		Id:   id,
		Name: name,
		Rule: rule,
	}

	// Upsert all the FQNs with the definition name mutation
	if name != "" {
		namespaceID := before.GetNamespace().GetId()
		attrFqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: id})
		c.logger.Debug("upserted attribute fqn with new definition name", slog.Any("fqn", attrFqn))
		if len(before.GetValues()) > 0 {
			for _, v := range before.GetValues() {
				fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: namespaceID, attributeID: id, valueID: v.GetId()})
				c.logger.Debug("upserted attribute value fqn with new definition name", slog.Any("fqn", fqn))
			}
		}
		attribute.Fqn = attrFqn
	}

	return attribute, nil
}

func (c PolicyDBClient) UpdateAttribute(ctx context.Context, id string, r *attributes.UpdateAttributeRequest) (*policy.Attribute, error) {
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetAttribute(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID:       id,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Attribute{
		Id:       id,
		Metadata: metadata,
	}, nil
}

func (c PolicyDBClient) DeactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	count, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID:     id,
		Active: pgtypeBool(false),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Attribute{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: false},
	}, nil
}

func (c PolicyDBClient) UnsafeReactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	count, err := c.Queries.UpdateAttribute(ctx, UpdateAttributeParams{
		ID:     id,
		Active: pgtypeBool(true),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Attribute{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: true},
	}, nil
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
