package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/service/pkg/db"
)

type dynamicValueMappingRow struct {
	id                           string
	attributeDefinitionID        string
	subjectExternalSelectorValue string
	operator                     int16
	subjectConditionSetID        pgtype.UUID
	actions                      interface{}
	metadata                     []byte
	namespace                    interface{}
}

func (c PolicyDBClient) CreateDynamicValueMapping(ctx context.Context, r *dynamicvaluemapping.CreateDynamicValueMappingRequest) (*policy.DynamicValueMapping, error) {
	resolver := r.GetValueResolver()
	if resolver.GetOperator() == policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_UNSPECIFIED {
		return nil, errors.Join(db.ErrEnumValueInvalid, errors.New("value_resolver.operator must be specified"))
	}

	attr, err := c.resolveDynamicValueMappingAttribute(ctx, r.GetAttributeDefinitionId(), r.GetAttributeDefinitionFqn())
	if err != nil {
		return nil, err
	}
	if err := validateDynamicValueMappingAttribute(attr); err != nil {
		return nil, err
	}

	// Enforce no-coexistence: a definition cannot have both value-level subject mappings
	// and a dynamic value entitlement mapping (DSPX-2754 / ADR 0005).
	if err := c.ensureNoValueSubjectMappingCoexistence(ctx, attr.GetId()); err != nil {
		return nil, err
	}

	resolvedNamespaceID, err := c.resolveNamespace(ctx, r.GetNamespaceId(), r.GetNamespaceFqn())
	if err != nil {
		return nil, err
	}
	parsedNamespaceID := pgtypeUUID(resolvedNamespaceID)

	actionIDs, err := c.resolveSubjectMappingActions(ctx, r.GetActions(), parsedNamespaceID)
	if err != nil {
		return nil, err
	}

	scs, err := c.resolveDynamicValueMappingSubjectConditionSet(ctx, r, resolvedNamespaceID)
	if err != nil {
		return nil, err
	}

	if err := c.validateDynamicValueMappingNamespaceConsistency(ctx, resolvedNamespaceID, attr, actionIDs, scs); err != nil {
		return nil, err
	}

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	createdID, err := c.queries.createDynamicValueMapping(ctx, createDynamicValueMappingParams{
		AttributeDefinitionID:        attr.GetId(),
		SubjectExternalSelectorValue: resolver.GetSubjectExternalSelectorValue(),
		Operator:                     int16(resolver.GetOperator()),
		Metadata:                     metadataJSON,
		SubjectConditionSetID:        pgtypeUUID(scs.GetId()),
		NamespaceID:                  parsedNamespaceID,
		ActionIds:                    actionIDs,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetDynamicValueMapping(ctx, createdID)
}

func (c PolicyDBClient) GetDynamicValueMapping(ctx context.Context, id string) (*policy.DynamicValueMapping, error) {
	row, err := c.queries.getDynamicValueMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if row.ID == "" {
		return nil, db.ErrNotFound
	}

	return c.hydrateDynamicValueMapping(ctx, dynamicValueMappingRow{
		id:                           row.ID,
		attributeDefinitionID:        row.AttributeDefinitionID,
		subjectExternalSelectorValue: row.SubjectExternalSelectorValue,
		operator:                     row.Operator,
		subjectConditionSetID:        row.SubjectConditionSetID,
		actions:                      row.Actions,
		metadata:                     row.Metadata,
		namespace:                    row.Namespace,
	})
}

func (c PolicyDBClient) ListDynamicValueMappings(ctx context.Context, r *dynamicvaluemapping.ListDynamicValueMappingsRequest) (*dynamicvaluemapping.ListDynamicValueMappingsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	sortField, sortDirection := GetDynamicValueMappingsSortParams(r.GetSort())

	rows, err := c.queries.listDynamicValueMappings(ctx, listDynamicValueMappingsParams{
		NamespaceID:           pgtypeUUID(r.GetNamespaceId()),
		NamespaceFqn:          pgtypeText(r.GetNamespaceFqn()),
		AttributeDefinitionID: pgtypeUUID(r.GetAttributeDefinitionId()),
		Limit:                 limit,
		Offset:                offset,
		SortField:             sortField,
		SortDirection:         sortDirection,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappings := make([]*policy.DynamicValueMapping, len(rows))
	for i, row := range rows {
		mapping, err := c.hydrateDynamicValueMapping(ctx, dynamicValueMappingRow{
			id:                           row.ID,
			attributeDefinitionID:        row.AttributeDefinitionID,
			subjectExternalSelectorValue: row.SubjectExternalSelectorValue,
			operator:                     row.Operator,
			subjectConditionSetID:        row.SubjectConditionSetID,
			actions:                      row.Actions,
			metadata:                     row.Metadata,
			namespace:                    row.Namespace,
		})
		if err != nil {
			return nil, err
		}
		mappings[i] = mapping
	}

	var (
		total      int32
		nextOffset int32
	)
	if len(rows) > 0 {
		total = int32(rows[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &dynamicvaluemapping.ListDynamicValueMappingsResponse{
		DynamicValueMappings: mappings,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) UpdateDynamicValueMapping(ctx context.Context, r *dynamicvaluemapping.UpdateDynamicValueMappingRequest) (*policy.DynamicValueMapping, error) {
	id := r.GetId()
	before, err := c.GetDynamicValueMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		return before.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	updateParams := updateDynamicValueMappingParams{
		ID:                    id,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgtypeUUID(r.GetSubjectConditionSetId()),
	}

	if resolver := r.GetValueResolver(); resolver != nil {
		if resolver.GetOperator() == policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_UNSPECIFIED {
			return nil, errors.Join(db.ErrEnumValueInvalid, errors.New("value_resolver.operator must be specified"))
		}
		updateParams.SubjectExternalSelectorValue = pgtypeText(resolver.GetSubjectExternalSelectorValue())
		updateParams.Operator = pgtype.Int2{Int16: int16(resolver.GetOperator()), Valid: true}
	}

	targetNamespaceID := before.GetNamespace().GetId()
	if actions := r.GetActions(); actions != nil {
		actionIDs, err := c.resolveSubjectMappingActions(ctx, actions, pgtypeUUID(targetNamespaceID))
		if err != nil {
			return nil, err
		}
		updateParams.ActionIds = actionIDs
	}

	count, err := c.queries.updateDynamicValueMapping(ctx, updateParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return c.GetDynamicValueMapping(ctx, id)
}

func (c PolicyDBClient) DeleteDynamicValueMapping(ctx context.Context, id string) (*policy.DynamicValueMapping, error) {
	count, err := c.queries.deleteDynamicValueMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.DynamicValueMapping{Id: id}, nil
}

func (c PolicyDBClient) hydrateDynamicValueMapping(ctx context.Context, row dynamicValueMappingRow) (*policy.DynamicValueMapping, error) {
	metadata := &common.Metadata{}
	if err := unmarshalMetadata(row.metadata, metadata); err != nil {
		return nil, err
	}

	actionsBytes, err := json.Marshal(row.actions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dynamic value mapping actions from interface{}: %w", err)
	}
	actions := []*policy.Action{}
	if err := unmarshalActionsProto(actionsBytes, &actions); err != nil {
		return nil, err
	}

	attr, err := c.GetAttribute(ctx, row.attributeDefinitionID)
	if err != nil {
		return nil, err
	}

	namespace, err := hydrateNamespaceFromInterface(row.namespace)
	if err != nil {
		return nil, err
	}

	mapping := &policy.DynamicValueMapping{
		Id:                  row.id,
		AttributeDefinition: attr,
		ValueResolver: &policy.DynamicValueResolver{
			SubjectExternalSelectorValue: row.subjectExternalSelectorValue,
			Operator:                     policy.DynamicValueOperatorEnum(row.operator),
		},
		Actions:   actions,
		Namespace: namespace,
		Metadata:  metadata,
	}

	// Optional static pre-gate.
	if row.subjectConditionSetID.Valid {
		scs, err := c.GetSubjectConditionSet(ctx, UUIDToString(row.subjectConditionSetID))
		if err != nil {
			return nil, err
		}
		mapping.SubjectConditionSet = scs
	}

	return mapping, nil
}

func (c PolicyDBClient) resolveDynamicValueMappingAttribute(ctx context.Context, id, fqn string) (*policy.Attribute, error) {
	switch {
	case id != "":
		return c.GetAttribute(ctx, id)
	case fqn != "":
		return c.GetAttribute(ctx, &attributes.GetAttributeRequest_Fqn{Fqn: fqn})
	default:
		return nil, db.WrapIfKnownInvalidQueryErr(
			errors.Join(db.ErrMissingValue, errors.New("either an attribute definition ID or FQN is required")),
		)
	}
}

func validateDynamicValueMappingAttribute(attr *policy.Attribute) error {
	switch attr.GetRule() {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		return nil
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		return errors.Join(db.ErrEnumValueInvalid, errors.New("dynamic value mappings do not support HIERARCHY attributes"))
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		fallthrough
	default:
		return errors.Join(db.ErrEnumValueInvalid, errors.New("dynamic value mappings require ALL_OF or ANY_OF attributes"))
	}
}

// ensureNoValueSubjectMappingCoexistence rejects creation of a dynamic mapping when the
// definition's values already carry value-level subject mappings.
func (c PolicyDBClient) ensureNoValueSubjectMappingCoexistence(ctx context.Context, definitionID string) error {
	count, err := c.queries.countValueSubjectMappingsByDefinitionID(ctx, definitionID)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	if count > 0 {
		return errors.Join(db.ErrRestrictViolation,
			fmt.Errorf("attribute definition [%s] already has value-level subject mappings; it cannot also have a dynamic value mapping", definitionID))
	}
	return nil
}

// ensureNoDynamicValueMappingCoexistence rejects creation of a value-level
// subject mapping when the value's parent definition already has a dynamic value
// entitlement mapping.
func (c PolicyDBClient) ensureNoDynamicValueMappingCoexistence(ctx context.Context, attributeValueID string) error {
	if attributeValueID == "" {
		return nil
	}
	definitionID, err := c.queries.getAttributeDefinitionIDByValueID(ctx, attributeValueID)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	count, err := c.queries.countDynamicValueMappingsByDefinitionID(ctx, definitionID)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	if count > 0 {
		return errors.Join(db.ErrRestrictViolation,
			fmt.Errorf("attribute definition [%s] has a dynamic value mapping; it cannot also have value-level subject mappings", definitionID))
	}
	return nil
}

func (c PolicyDBClient) resolveDynamicValueMappingSubjectConditionSet(
	ctx context.Context,
	r *dynamicvaluemapping.CreateDynamicValueMappingRequest,
	namespaceID string,
) (*policy.SubjectConditionSet, error) {
	switch {
	case r.GetExistingSubjectConditionSetId() != "":
		scs, err := c.GetSubjectConditionSet(ctx, r.GetExistingSubjectConditionSetId())
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		return scs, nil
	case r.GetNewSubjectConditionSet() != nil:
		scs, err := c.CreateSubjectConditionSet(ctx, r.GetNewSubjectConditionSet(), namespaceID, "")
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		return scs, nil
	default:
		// The static pre-gate is optional; no SubjectConditionSet is a valid state.
		return nil, nil //nolint:nilnil // optional pre-gate: nil SCS with nil error is intentional
	}
}

func (c PolicyDBClient) validateDynamicValueMappingNamespaceConsistency(
	ctx context.Context,
	targetNsID string,
	attr *policy.Attribute,
	actionIDs []string,
	scs *policy.SubjectConditionSet,
) error {
	if targetNsID != "" && attr.GetNamespace().GetId() != targetNsID {
		return errors.Join(db.ErrNamespaceMismatch,
			fmt.Errorf("attribute definition namespace [%s] does not match the specified dynamic value mapping namespace [%s]", attr.GetNamespace().GetId(), targetNsID))
	}

	if len(actionIDs) > 0 {
		actionRows, err := c.queries.getActionsByIDs(ctx, actionIDs)
		if err != nil {
			return db.WrapIfKnownInvalidQueryErr(err)
		}
		for _, a := range actionRows {
			actionNsID := UUIDToString(a.NamespaceID)
			if actionNsID != targetNsID {
				return errors.Join(db.ErrNamespaceMismatch,
					fmt.Errorf("action [%s] namespace [%s] does not match the specified dynamic value mapping namespace [%s]", a.ID, actionNsID, targetNsID))
			}
		}
	}

	if scs != nil && scs.GetNamespace().GetId() != targetNsID {
		return errors.Join(db.ErrNamespaceMismatch,
			fmt.Errorf("subject condition set [%s] namespace [%s] does not match the specified dynamic value mapping namespace [%s]", scs.GetId(), scs.GetNamespace().GetId(), targetNsID))
	}

	return nil
}
