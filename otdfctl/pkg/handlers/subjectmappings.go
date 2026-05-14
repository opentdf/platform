package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

const (
	SubjectMappingOperatorIn          = "IN"
	SubjectMappingOperatorNotIn       = "NOT_IN"
	SubjectMappingOperatorInContains  = "IN_CONTAINS"
	SubjectMappingOperatorUnspecified = "UNSPECIFIED"
)

var SubjectMappingOperatorEnumChoices = []string{SubjectMappingOperatorIn, SubjectMappingOperatorNotIn, SubjectMappingOperatorUnspecified}

func (h Handler) GetSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	resp, err := h.sdk.SubjectMapping.GetSubjectMapping(ctx, &subjectmapping.GetSubjectMappingRequest{
		Id: id,
	})
	return resp.GetSubjectMapping(), err
}

func (h Handler) ListSubjectMappings(ctx context.Context, limit, offset int32, namespace string, sort SortOption) (*subjectmapping.ListSubjectMappingsResponse, error) {
	req := &subjectmapping.ListSubjectMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	}
	req.NamespaceId, req.NamespaceFqn = getNamespaceIDAndFQN(namespace)
	if !sort.IsZero() {
		var field subjectmapping.SortSubjectMappingsType
		if sort.Field != "" {
			var ok bool
			allowedFields := map[string]subjectmapping.SortSubjectMappingsType{
				"created_at": subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_CREATED_AT,
				"updated_at": subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UPDATED_AT,
			}
			field, ok = allowedFields[sort.Field]
			if !ok {
				return nil, invalidSortFieldError("subject mappings", sort.Field, allowedFields)
			}
		}
		req.Sort = []*subjectmapping.SubjectMappingsSort{{Field: field, Direction: sort.Direction}}
	}
	return h.sdk.SubjectMapping.ListSubjectMappings(ctx, req)
}

// Creates and returns the created subject mapping
func (h Handler) CreateNewSubjectMapping(ctx context.Context, attrValID string, actions []*policy.Action, existingSCSId string, newScs *subjectmapping.SubjectConditionSetCreate, m *common.MetadataMutable, namespace string) (*policy.SubjectMapping, error) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              attrValID,
		Actions:                       actions,
		ExistingSubjectConditionSetId: existingSCSId,
		NewSubjectConditionSet:        newScs,
		Metadata:                      m,
	}
	req.NamespaceId, req.NamespaceFqn = getNamespaceIDAndFQN(namespace)
	resp, err := h.sdk.SubjectMapping.CreateSubjectMapping(ctx, req)
	if err != nil {
		return nil, err
	}
	return h.GetSubjectMapping(ctx, resp.GetSubjectMapping().GetId())
}

// Updates and returns the updated subject mapping
func (h Handler) UpdateSubjectMapping(ctx context.Context, id string, updatedSCSId string, updatedActions []*policy.Action, metadata *common.MetadataMutable, metadataBehavior common.MetadataUpdateEnum) (*policy.SubjectMapping, error) {
	_, err := h.sdk.SubjectMapping.UpdateSubjectMapping(ctx, &subjectmapping.UpdateSubjectMappingRequest{
		Id:                     id,
		SubjectConditionSetId:  updatedSCSId,
		Actions:                updatedActions,
		MetadataUpdateBehavior: metadataBehavior,
		Metadata:               metadata,
	})
	if err != nil {
		return nil, err
	}
	return h.GetSubjectMapping(ctx, id)
}

func (h Handler) DeleteSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	resp, err := h.sdk.SubjectMapping.DeleteSubjectMapping(ctx, &subjectmapping.DeleteSubjectMappingRequest{
		Id: id,
	})
	return resp.GetSubjectMapping(), err
}

func (h Handler) MatchSubjectMappings(ctx context.Context, selectors []string) ([]*policy.SubjectMapping, error) {
	subjectProperties := make([]*policy.SubjectProperty, len(selectors))
	for i, selector := range selectors {
		subjectProperties[i] = &policy.SubjectProperty{
			ExternalSelectorValue: selector,
		}
	}
	resp, err := h.sdk.SubjectMapping.MatchSubjectMappings(ctx, &subjectmapping.MatchSubjectMappingsRequest{
		SubjectProperties: subjectProperties,
	})
	return resp.GetSubjectMappings(), err
}

func GetSubjectMappingOperatorFromChoice(readable string) policy.SubjectMappingOperatorEnum {
	switch readable {
	case SubjectMappingOperatorIn:
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN
	case SubjectMappingOperatorNotIn:
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN
	case SubjectMappingOperatorInContains:
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS
	case SubjectMappingOperatorUnspecified:
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED
	default:
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED
	}
}

func GetSubjectMappingOperatorChoiceFromEnum(enum policy.SubjectMappingOperatorEnum) string {
	switch enum {
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN:
		return SubjectMappingOperatorIn
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN:
		return SubjectMappingOperatorNotIn
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS:
		return SubjectMappingOperatorInContains
	case policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED:
		return SubjectMappingOperatorUnspecified
	default:
		return SubjectMappingOperatorUnspecified
	}
}
