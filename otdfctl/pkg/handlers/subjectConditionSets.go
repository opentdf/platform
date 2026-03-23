package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

func (h Handler) GetSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	resp, err := h.sdk.SubjectMapping.GetSubjectConditionSet(ctx, &subjectmapping.GetSubjectConditionSetRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetSubjectConditionSet(), nil
}

func (h Handler) ListSubjectConditionSets(ctx context.Context, limit, offset int32) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	return h.sdk.SubjectMapping.ListSubjectConditionSets(ctx, &subjectmapping.ListSubjectConditionSetsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

// Creates and returns the created subject condition set
func (h Handler) CreateSubjectConditionSet(ctx context.Context, ss []*policy.SubjectSet, metadata *common.MetadataMutable) (*policy.SubjectConditionSet, error) {
	resp, err := h.sdk.SubjectMapping.CreateSubjectConditionSet(ctx, &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
			SubjectSets: ss,
			Metadata:    metadata,
		},
	})
	if err != nil {
		return nil, err
	}
	return h.GetSubjectConditionSet(ctx, resp.GetSubjectConditionSet().GetId())
}

// Updates and returns the updated subject condition set
func (h Handler) UpdateSubjectConditionSet(ctx context.Context, id string, ss []*policy.SubjectSet, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.SubjectConditionSet, error) {
	_, err := h.sdk.SubjectMapping.UpdateSubjectConditionSet(ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     id,
		SubjectSets:            ss,
		Metadata:               metadata,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}
	return h.GetSubjectConditionSet(ctx, id)
}

func (h Handler) DeleteSubjectConditionSet(ctx context.Context, id string) error {
	_, err := h.sdk.SubjectMapping.DeleteSubjectConditionSet(ctx, &subjectmapping.DeleteSubjectConditionSetRequest{
		Id: id,
	})
	return err
}

func (h Handler) PruneSubjectConditionSets(ctx context.Context) ([]*policy.SubjectConditionSet, error) {
	rsp, err := h.sdk.SubjectMapping.DeleteAllUnmappedSubjectConditionSets(ctx, &subjectmapping.DeleteAllUnmappedSubjectConditionSetsRequest{})
	if err != nil {
		return nil, err
	}
	return rsp.GetSubjectConditionSets(), nil
}
