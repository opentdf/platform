package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

	if valuesJSON != nil {
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
	}

	return values, nil
}

type attributeQueryRow struct {
	id             string
	name           string
	rule           string
	allowTraversal bool
	metadataJSON   []byte
	namespaceID    string
	active         bool
	namespaceName  string
	valuesJSON     []byte
	grantsJSON     []byte
	fqn            sql.NullString
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
		Fqn:  "https://" + row.namespaceName,
	}

	attr := &policy.Attribute{
		Id:             row.id,
		Name:           row.name,
		Rule:           attributesRuleTypeEnumTransformOut(row.rule),
		Values:         values,
		AllowTraversal: &wrapperspb.BoolValue{Value: row.allowTraversal},
		Active:         &wrapperspb.BoolValue{Value: row.active},
		Metadata:       metadata,
		Namespace:      ns,
		Grants:         grants,
		Fqn:            row.fqn.String,
	}

	return attr, nil
}

///
// CRUD operations
///

func (c PolicyDBClient) ListAttributes(ctx context.Context, r *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	namespace := r.GetNamespace()
	state := getDBStateTypeTransformedEnum(r.GetState())
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	var (
		active = pgtype.Bool{
			Valid: false,
		}
		namespaceID   = ""
		namespaceName = ""
	)

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	if state != stateAny {
		active = pgtypeBool(state == stateActive)
	}

	if namespace != "" {
		if _, err := uuid.Parse(namespace); err == nil {
			namespaceID = namespace
		} else {
			namespaceName = strings.ToLower(namespace)
		}
	}

	list, err := c.queries.listAttributesDetail(ctx, listAttributesDetailParams{
		Active:        active,
		NamespaceID:   pgtypeUUID(namespaceID),
		NamespaceName: pgtypeText(namespaceName),
		Limit:         limit,
		Offset:        offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	policyAttributes := make([]*policy.Attribute, len(list))

	for i, attr := range list {
		policyAttributes[i], err = hydrateAttribute(&attributeQueryRow{
			id:             attr.ID,
			name:           attr.AttributeName,
			rule:           string(attr.Rule),
			allowTraversal: attr.AllowTraversal,
			active:         attr.Active,
			metadataJSON:   attr.Metadata,
			namespaceID:    attr.NamespaceID,
			namespaceName:  attr.NamespaceName.String,
			valuesJSON:     attr.Values,
			fqn:            sql.NullString(attr.Fqn),
		})
		if err != nil {
			return nil, err
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &attributes.ListAttributesResponse{
		Attributes: policyAttributes,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) GetAttribute(ctx context.Context, identifier any) (*policy.Attribute, error) {
	var (
		attr   getAttributeRow
		err    error
		params getAttributeParams
	)

	switch i := identifier.(type) {
	case *attributes.GetAttributeRequest_AttributeId:
		id := pgtypeUUID(i.AttributeId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getAttributeParams{ID: id}
	case *attributes.GetAttributeRequest_Fqn:
		fqn := pgtypeText(i.Fqn)
		if !fqn.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = getAttributeParams{Fqn: pgtypeText(i.Fqn)}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getAttributeParams{ID: id}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrSelectIdentifierInvalid, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	attr, err = c.queries.getAttribute(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	policyAttr, err := hydrateAttribute(&attributeQueryRow{
		id:             attr.ID,
		name:           attr.AttributeName,
		rule:           string(attr.Rule),
		allowTraversal: attr.AllowTraversal,
		active:         attr.Active,
		metadataJSON:   attr.Metadata,
		namespaceID:    attr.NamespaceID,
		namespaceName:  attr.NamespaceName.String,
		valuesJSON:     attr.Values,
		grantsJSON:     attr.Grants,
		fqn:            sql.NullString(attr.Fqn),
	})
	if err != nil {
		return nil, err
	}

	var keys []*policy.SimpleKasKey
	if len(attr.Keys) > 0 {
		keys, err = db.SimpleKasKeysProtoJSON(attr.Keys)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal keys [%s]: %w", string(attr.Keys), err)
		}
		policyAttr.KasKeys = keys
	}

	return policyAttr, nil
}

func (c PolicyDBClient) ListAttributesByFqns(ctx context.Context, fqns []string, includeInactiveValues bool) ([]*policy.Attribute, error) {
	list, err := c.queries.listAttributesByDefOrValueFqns(ctx, listAttributesByDefOrValueFqnsParams{
		Fqns:                  fqns,
		IncludeInactiveValues: includeInactiveValues,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attrs := make([]*policy.Attribute, len(list))
	for i, attr := range list {
		ns := new(policy.Namespace)
		err = protojson.Unmarshal(attr.Namespace, ns)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal namespace [%s]: %w", string(attr.Namespace), err)
		}

		values, err := attributesValuesProtojson(attr.Values)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal values [%s]: %w", string(attr.Values), err)
		}

		var keys []*policy.SimpleKasKey
		var grants []*policy.KeyAccessServer
		if len(attr.Grants) > 0 {
			grants, err = db.KeyAccessServerProtoJSON(attr.Grants)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal grants [%s]: %w", string(attr.Grants), err)
			}
		}
		if len(attr.Keys) > 0 {
			keys, err = db.SimpleKasKeysProtoJSON(attr.Keys)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal keys [%s]: %w", string(attr.Keys), err)
			}

			grants, err = mapKasKeysToGrants(keys, grants, c.logger)
			if err != nil {
				return nil, fmt.Errorf("failed to map keys to grants: %w", err)
			}
		}

		for _, val := range values {
			if val.GetKasKeys() == nil {
				continue
			}

			valGrants, err := mapKasKeysToGrants(val.GetKasKeys(), val.GetGrants(), c.logger)
			if err != nil {
				return nil, fmt.Errorf("failed to map keys to grants: %w", err)
			}
			val.Grants = valGrants
		}

		nsGrants, err := mapKasKeysToGrants(ns.GetKasKeys(), ns.GetGrants(), c.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to map keys to grants: %w", err)
		}
		ns.Grants = nsGrants

		attrs[i] = &policy.Attribute{
			Id:             attr.ID,
			Name:           attr.Name,
			Rule:           attributesRuleTypeEnumTransformOut(string(attr.Rule)),
			AllowTraversal: &wrapperspb.BoolValue{Value: attr.AllowTraversal},
			Fqn:            attr.Fqn,
			Active:         &wrapperspb.BoolValue{Value: attr.Active},
			Namespace:      ns,
			Grants:         grants,
			Values:         values,
			KasKeys:        keys,
		}
	}

	return attrs, nil
}

func (c PolicyDBClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
	list, err := c.ListAttributesByFqns(ctx, []string{strings.ToLower(fqn)}, false)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if len(list) != 1 {
		return nil, db.ErrNotFound
	}

	attr := list[0]
	return attr, nil
}

func (c PolicyDBClient) GetAttributesByNamespace(ctx context.Context, namespaceID string) ([]*policy.Attribute, error) {
	list, err := c.queries.listAttributesSummary(ctx, listAttributesSummaryParams{
		NamespaceID: namespaceID,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	policyAttributes := make([]*policy.Attribute, len(list))

	for i, attr := range list {
		policyAttributes[i], err = hydrateAttribute(&attributeQueryRow{
			id:             attr.ID,
			name:           attr.AttributeName,
			rule:           string(attr.Rule),
			allowTraversal: attr.AllowTraversal,
			active:         attr.Active,
			metadataJSON:   attr.Metadata,
			namespaceID:    attr.NamespaceID,
			namespaceName:  attr.NamespaceName.String,
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
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	ruleString := attributesRuleTypeEnumTransformIn(r.GetRule().String())

	createdID, err := c.queries.createAttribute(ctx, createAttributeParams{
		NamespaceID:    namespaceID,
		Name:           name,
		Rule:           AttributeDefinitionRule(ruleString),
		Metadata:       metadataJSON,
		AllowTraversal: r.GetAllowTraversal().GetValue(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Add values
	for _, v := range r.GetValues() {
		req := &attributes.CreateAttributeValueRequest{
			AttributeId: createdID,
			Value:       v,
		}
		_, err := c.CreateAttributeValue(ctx, createdID, req)
		if err != nil {
			return nil, err
		}
	}

	// Update the FQNs
	_, err = c.queries.upsertAttributeDefinitionFqn(ctx, createdID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttribute(ctx, createdID)
}

func (c PolicyDBClient) UnsafeUpdateAttribute(ctx context.Context, r *unsafe.UnsafeUpdateAttributeRequest) (*policy.Attribute, error) {
	id := r.GetId()
	name := strings.ToLower(r.GetName())
	rule := r.GetRule()
	var allowTraversal pgtype.Bool
	if r.GetAllowTraversal() == nil {
		allowTraversal = pgtype.Bool{Valid: false}
	} else {
		allowTraversal = pgtypeBool(r.GetAllowTraversal().GetValue())
	}
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

	count, err := c.queries.updateAttribute(ctx, updateAttributeParams{
		ID:   id,
		Name: pgtypeText(name),
		Rule: NullAttributeDefinitionRule{
			AttributeDefinitionRule: AttributeDefinitionRule(ruleString),
			Valid:                   ruleString != "",
		},
		AllowTraversal: allowTraversal,
		ValuesOrder:    r.GetValuesOrder(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// Upsert all the FQNs with the definition name mutation
	if name != "" {
		_, err = c.queries.upsertAttributeDefinitionFqn(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
	}

	return c.GetAttribute(ctx, id)
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

	count, err := c.queries.updateAttribute(ctx, updateAttributeParams{
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
	count, err := c.queries.updateAttribute(ctx, updateAttributeParams{
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
	count, err := c.queries.updateAttribute(ctx, updateAttributeParams{
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

	count, err := c.queries.deleteAttribute(ctx, id)
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

func (c PolicyDBClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	count, err := c.queries.removeKeyAccessServerFromAttribute(ctx, removeKeyAccessServerFromAttributeParams{
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

func (c PolicyDBClient) AssignPublicKeyToAttribute(ctx context.Context, k *attributes.AttributeKey) (*attributes.AttributeKey, error) {
	if err := c.verifyKeyIsActive(ctx, k.GetKeyId()); err != nil {
		return nil, err
	}

	ak, err := c.queries.assignPublicKeyToAttributeDefinition(ctx, assignPublicKeyToAttributeDefinitionParams{
		DefinitionID:         k.GetAttributeId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &attributes.AttributeKey{
		AttributeId: ak.DefinitionID,
		KeyId:       ak.KeyAccessServerKeyID,
	}, nil
}

func (c PolicyDBClient) RemovePublicKeyFromAttribute(ctx context.Context, k *attributes.AttributeKey) (*attributes.AttributeKey, error) {
	count, err := c.queries.removePublicKeyFromAttributeDefinition(ctx, removePublicKeyFromAttributeDefinitionParams{
		DefinitionID:         k.GetAttributeId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &attributes.AttributeKey{
		AttributeId: k.GetAttributeId(),
		KeyId:       k.GetKeyId(),
	}, nil
}
