package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
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
			// Normalize SQLite timestamps and boolean values for protojson compatibility
			normalized := normalizeSQLiteTimestamps(r)
			err := protojson.Unmarshal(normalized, value)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling a value: %w", err)
			}
			// Post-process KasKeys to decode base64-encoded PEM values (SQLite compatibility)
			decodeBase64PemInKasKeys(value.GetKasKeys())
			values = append(values, value)
		}
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
		Fqn:  "https://" + row.namespaceName,
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

func (c PolicyDBClient) ListAttributes(ctx context.Context, r *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	namespace := r.GetNamespace()
	state := getDBStateTypeTransformedEnum(r.GetState())
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())
	var (
		active        *bool
		namespaceID   = ""
		namespaceName = ""
	)

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	if state != stateAny {
		isActive := state == stateActive
		active = &isActive
	}

	if namespace != "" {
		if _, err := uuid.Parse(namespace); err == nil {
			namespaceID = namespace
		} else {
			namespaceName = strings.ToLower(namespace)
		}
	}

	list, err := c.router.ListAttributesDetail(ctx, UnifiedListAttributesDetailParams{
		Active:        active,
		NamespaceID:   namespaceID,
		NamespaceName: namespaceName,
		Limit:         limit,
		Offset:        offset,
	})
	if err != nil {
		return nil, c.WrapError(err)
	}

	policyAttributes := make([]*policy.Attribute, len(list))

	for i, attr := range list {
		policyAttributes[i], err = hydrateAttribute(&attributeQueryRow{
			id:            attr.ID,
			name:          attr.AttributeName,
			rule:          attr.Rule,
			active:        attr.Active,
			metadataJSON:  attr.Metadata,
			namespaceID:   attr.NamespaceID,
			namespaceName: attr.NamespaceName.String,
			valuesJSON:    attr.Values,
			fqn:           attr.Fqn,
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
		params UnifiedGetAttributeParams
	)

	switch i := identifier.(type) {
	case *attributes.GetAttributeRequest_AttributeId:
		id := pgtypeUUID(i.AttributeId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = UnifiedGetAttributeParams{ID: i.AttributeId}
	case *attributes.GetAttributeRequest_Fqn:
		fqn := pgtypeText(i.Fqn)
		if !fqn.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = UnifiedGetAttributeParams{Fqn: i.Fqn}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = UnifiedGetAttributeParams{ID: i}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrSelectIdentifierInvalid, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	attr, err := c.router.GetAttribute(ctx, params)
	if err != nil {
		return nil, c.WrapError(err)
	}

	policyAttr, err := hydrateAttribute(&attributeQueryRow{
		id:            attr.ID,
		name:          attr.AttributeName,
		rule:          attr.Rule,
		active:        attr.Active,
		metadataJSON:  attr.Metadata,
		namespaceID:   attr.NamespaceID,
		namespaceName: attr.NamespaceName.String,
		valuesJSON:    attr.Values,
		grantsJSON:    attr.Grants,
		fqn:           attr.Fqn,
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

func (c PolicyDBClient) ListAttributesByFqns(ctx context.Context, fqns []string) ([]*policy.Attribute, error) {
	list, err := c.router.ListAttributesByDefOrValueFqns(ctx, fqns)
	if err != nil {
		return nil, c.WrapError(err)
	}

	attrs := make([]*policy.Attribute, len(list))
	for i, attr := range list {
		ns := new(policy.Namespace)
		if err = unmarshalNamespace(attr.Namespace, ns); err != nil {
			return nil, err
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
			Id:        attr.ID,
			Name:      attr.Name,
			Rule:      attributesRuleTypeEnumTransformOut(attr.Rule),
			Fqn:       attr.Fqn,
			Active:    &wrapperspb.BoolValue{Value: attr.Active},
			Namespace: ns,
			Grants:    grants,
			Values:    values,
			KasKeys:   keys,
		}
	}

	return attrs, nil
}

func (c PolicyDBClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
	list, err := c.ListAttributesByFqns(ctx, []string{strings.ToLower(fqn)})
	if err != nil {
		return nil, c.WrapError(err)
	}

	if len(list) != 1 {
		return nil, db.ErrNotFound
	}

	attr := list[0]
	return attr, nil
}

func (c PolicyDBClient) GetAttributesByNamespace(ctx context.Context, namespaceID string) ([]*policy.Attribute, error) {
	list, err := c.router.ListAttributesSummary(ctx, UnifiedListAttributesSummaryParams{
		NamespaceID: namespaceID,
	})
	if err != nil {
		return nil, c.WrapError(err)
	}

	policyAttributes := make([]*policy.Attribute, len(list))

	for i, attr := range list {
		policyAttributes[i], err = hydrateAttribute(&attributeQueryRow{
			id:            attr.ID,
			name:          attr.AttributeName,
			rule:          attr.Rule,
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
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}
	ruleString := attributesRuleTypeEnumTransformIn(r.GetRule().String())

	createdID, err := c.router.CreateAttribute(ctx, UnifiedCreateAttributeParams{
		NamespaceID: namespaceID,
		Name:        name,
		Rule:        ruleString,
		Metadata:    metadataJSON,
	})
	if err != nil {
		return nil, c.WrapError(err)
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
	_, err = c.router.UpsertAttributeDefinitionFqn(ctx, createdID)
	if err != nil {
		return nil, c.WrapError(err)
	}

	return c.GetAttribute(ctx, createdID)
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
	var rulePtr *string
	if rule != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED {
		ruleString := attributesRuleTypeEnumTransformIn(rule.String())
		rulePtr = &ruleString
	}

	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	count, err := c.router.UpdateAttribute(ctx, UnifiedUpdateAttributeParams{
		ID:          id,
		Name:        namePtr,
		Rule:        rulePtr,
		ValuesOrder: r.GetValuesOrder(),
	})
	if err != nil {
		return nil, c.WrapError(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// Upsert all the FQNs with the definition name mutation
	if name != "" {
		_, err = c.router.UpsertAttributeDefinitionFqn(ctx, id)
		if err != nil {
			return nil, c.WrapError(err)
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

	count, err := c.router.UpdateAttribute(ctx, UnifiedUpdateAttributeParams{
		ID:       id,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, c.WrapError(err)
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
	// Use transaction for atomicity - PostgreSQL triggers work within transactions,
	// SQLite needs explicit cascade which is also wrapped in this transaction.
	var result *policy.Attribute
	active := false
	err := c.RunInTx(ctx, func(txClient *PolicyDBClient) error {
		count, err := txClient.router.UpdateAttribute(ctx, UnifiedUpdateAttributeParams{
			ID:     id,
			Active: &active,
		})
		if err != nil {
			return c.WrapError(err)
		}
		if count == 0 {
			return db.ErrNotFound
		}

		// For SQLite: cascade deactivation to attribute values
		// (PostgreSQL handles this via trigger, this is a no-op for PostgreSQL)
		if err := txClient.CascadeDeactivateDefinition(ctx, id); err != nil {
			return fmt.Errorf("failed to cascade deactivation: %w", err)
		}

		result = &policy.Attribute{
			Id:     id,
			Active: &wrapperspb.BoolValue{Value: false},
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c PolicyDBClient) UnsafeReactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	active := true
	count, err := c.router.UpdateAttribute(ctx, UnifiedUpdateAttributeParams{
		ID:     id,
		Active: &active,
	})
	if err != nil {
		return nil, c.WrapError(err)
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

	count, err := c.router.DeleteAttribute(ctx, id)
	if err != nil {
		return nil, c.WrapError(err)
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
	count, err := c.router.RemoveKeyAccessServerFromAttribute(ctx, UnifiedRemoveKeyAccessServerFromAttributeParams{
		AttributeDefinitionID: k.GetAttributeId(),
		KeyAccessServerID:     k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, c.WrapError(err)
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

	ak, err := c.router.AssignPublicKeyToAttributeDefinition(ctx, UnifiedAssignPublicKeyToAttributeDefinitionParams{
		DefinitionID:         k.GetAttributeId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, c.WrapError(err)
	}

	return &attributes.AttributeKey{
		AttributeId: ak.DefinitionID,
		KeyId:       ak.KeyAccessServerKeyID,
	}, nil
}

func (c PolicyDBClient) RemovePublicKeyFromAttribute(ctx context.Context, k *attributes.AttributeKey) (*attributes.AttributeKey, error) {
	count, err := c.router.RemovePublicKeyFromAttributeDefinition(ctx, UnifiedRemovePublicKeyFromAttributeDefinitionParams{
		DefinitionID:         k.GetAttributeId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, c.WrapError(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &attributes.AttributeKey{
		AttributeId: k.GetAttributeId(),
		KeyId:       k.GetKeyId(),
	}, nil
}
