package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

// Helper to marshal SubjectSets into JSON (stored as JSONB in the database column)
func marshalSubjectSetsProto(subjectSet []*policy.SubjectSet) ([]byte, error) {
	var raw []json.RawMessage
	for _, ss := range subjectSet {
		b, err := protojson.Marshal(ss)
		if err != nil {
			// todo: can ss be included in the error message?
			return nil, fmt.Errorf("failed to marshall subject set: %w", err)
		}
		raw = append(raw, b)
	}
	return json.Marshal(raw)
}

// Helper to unmarshal SubjectSets from JSON (stored as JSONB in the database column)
func unmarshalSubjectSetsProto(conditionJSON []byte) ([]*policy.SubjectSet, error) {
	var (
		raw []json.RawMessage
		ss  []*policy.SubjectSet
	)
	if err := json.Unmarshal(conditionJSON, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subject sets array [%s]: %w", string(conditionJSON), err)
	}

	for _, r := range raw {
		s := policy.SubjectSet{}
		if err := protojson.Unmarshal(r, &s); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subject set [%s]: %w", string(r), err)
		}
		ss = append(ss, &s)
	}

	return ss, nil
}

// Helper to marshal Actions into JSON (stored as JSONB in the database column)
func marshalActionsProto(actions []*policy.Action) ([]byte, error) {
	var raw []json.RawMessage
	for _, a := range actions {
		b, err := protojson.Marshal(a)
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
	}
	return json.Marshal(raw)
}

func unmarshalActionsProto(actionsJSON []byte, actions *[]*policy.Action) error {
	var raw []json.RawMessage

	if actionsJSON != nil {
		if err := json.Unmarshal(actionsJSON, &raw); err != nil {
			return fmt.Errorf("failed to unmarshal actions array [%s]: %w", string(actionsJSON), err)
		}

		for _, r := range raw {
			a := policy.Action{}
			if err := protojson.Unmarshal(r, &a); err != nil {
				return fmt.Errorf("failed to unmarshal action [%s]: %w", string(r), err)
			}
			*actions = append(*actions, &a)
		}
	}

	return nil
}

/*
	Subject Condition Sets
*/

// Creates a new subject condition set and returns it
func (c PolicyDBClient) CreateSubjectConditionSet(ctx context.Context, s *subjectmapping.SubjectConditionSetCreate) (*policy.SubjectConditionSet, error) {
	subjectSets := s.GetSubjectSets()
	conditionJSON, err := marshalSubjectSetsProto(subjectSets)
	if err != nil {
		return nil, err
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateSubjectConditionSet(ctx, CreateSubjectConditionSetParams{
		Condition: conditionJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectConditionSet{
		Id:          createdID,
		SubjectSets: subjectSets,
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) GetSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	cs, err := c.Queries.GetSubjectConditionSet(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(cs.Metadata, metadata); err != nil {
		return nil, err
	}

	sets, err := unmarshalSubjectSetsProto(cs.Condition)
	if err != nil {
		return nil, err
	}

	return &policy.SubjectConditionSet{
		Id:          id,
		SubjectSets: sets,
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) ListSubjectConditionSets(ctx context.Context, r *subjectmapping.ListSubjectConditionSetsRequest) (*subjectmapping.ListSubjectConditionSetsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.Queries.ListSubjectConditionSets(ctx, ListSubjectConditionSetsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	setList := make([]*policy.SubjectConditionSet, len(list))
	for i, set := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(set.Metadata, metadata); err != nil {
			return nil, err
		}

		sets, err := unmarshalSubjectSetsProto(set.Condition)
		if err != nil {
			return nil, err
		}

		setList[i] = &policy.SubjectConditionSet{
			Id:          set.ID,
			SubjectSets: sets,
			Metadata:    metadata,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &subjectmapping.ListSubjectConditionSetsResponse{
		SubjectConditionSets: setList,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

// Mutates provided fields and returns the updated subject condition set
func (c PolicyDBClient) UpdateSubjectConditionSet(ctx context.Context, r *subjectmapping.UpdateSubjectConditionSetRequest) (*policy.SubjectConditionSet, error) {
	id := r.GetId()
	subjectSets := r.GetSubjectSets()
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		scs, err := c.GetSubjectConditionSet(ctx, id)
		if err != nil {
			return nil, err
		}
		return scs.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var conditionJSON []byte
	if subjectSets != nil {
		conditionJSON, err = marshalSubjectSetsProto(subjectSets)
		if err != nil {
			return nil, err
		}
	}

	count, err := c.Queries.UpdateSubjectConditionSet(ctx, UpdateSubjectConditionSetParams{
		ID:        id,
		Condition: conditionJSON,
		Metadata:  metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectConditionSet{
		Id:          id,
		SubjectSets: subjectSets,
		Metadata:    metadata,
	}, nil
}

// Deletes specified subject condition set and returns the id of the deleted
func (c PolicyDBClient) DeleteSubjectConditionSet(ctx context.Context, id string) (*policy.SubjectConditionSet, error) {
	count, err := c.Queries.DeleteSubjectConditionSet(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectConditionSet{
		Id: id,
	}, nil
}

// Deletes/prunes all subject condition sets not referenced within a subject mapping
func (c PolicyDBClient) DeleteAllUnmappedSubjectConditionSets(ctx context.Context) ([]*policy.SubjectConditionSet, error) {
	deletedIDs, err := c.Queries.DeleteAllUnmappedSubjectConditionSets(ctx)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if len(deletedIDs) == 0 {
		return nil, db.ErrNotFound
	}

	setList := make([]*policy.SubjectConditionSet, len(deletedIDs))
	for i, id := range deletedIDs {
		setList[i] = &policy.SubjectConditionSet{
			Id: id,
		}
	}
	return setList, nil
}

/*
	Subject Mappings
*/

// Creates a new subject mapping and returns it. If an existing subject condition set id is provided, it will be used.
// If a new subject condition set is provided, it will be created. The existing subject condition set id takes precedence.
func (c PolicyDBClient) CreateSubjectMapping(ctx context.Context, s *subjectmapping.CreateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	actions := s.GetActions()
	attributeValueID := s.GetAttributeValueId()

	var (
		scs *policy.SubjectConditionSet
		err error
	)

	// Prefer existing id over new creation per documented proto behavior.
	switch {
	case s.GetExistingSubjectConditionSetId() != "":
		scs, err = c.GetSubjectConditionSet(ctx, s.GetExistingSubjectConditionSetId())
		if err != nil {
			return nil, err
		}
	case s.GetNewSubjectConditionSet() != nil:
		// create the new subject condition set
		scs, err = c.CreateSubjectConditionSet(ctx, s.GetNewSubjectConditionSet())
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Join(db.ErrMissingValue, errors.New("either an existing Subject Condition Set ID or a new Subject Condition Set is required when creating a subject mapping"))
	}

	metadataJSON, metadata, err := db.MarshalCreateMetadata(s.GetMetadata())
	if err != nil {
		return nil, err
	}

	actionsJSON, err := marshalActionsProto(actions)
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateSubjectMapping(ctx, CreateSubjectMappingParams{
		AttributeValueID:      attributeValueID,
		Actions:               actionsJSON,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgtypeUUID(scs.GetId()),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.SubjectMapping{
		Id: createdID,
		AttributeValue: &policy.Value{
			Id: attributeValueID,
		},
		SubjectConditionSet: scs,
		Actions:             actions,
		Metadata:            metadata,
	}, nil
}

func (c PolicyDBClient) GetSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	sm, err := c.Queries.GetSubjectMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(sm.Metadata, metadata); err != nil {
		return nil, err
	}

	av := &policy.Value{}
	if err = unmarshalAttributeValue(sm.AttributeValue, av); err != nil {
		return nil, err
	}

	a := []*policy.Action{}
	if err = unmarshalActionsProto(sm.Actions, &a); err != nil {
		return nil, err
	}

	scs := policy.SubjectConditionSet{}
	if err = unmarshalSubjectConditionSet(sm.SubjectConditionSet, &scs); err != nil {
		return nil, err
	}

	return &policy.SubjectMapping{
		Id:                  id,
		Metadata:            metadata,
		AttributeValue:      av,
		SubjectConditionSet: &scs,
		Actions:             a,
	}, nil
}

func (c PolicyDBClient) ListSubjectMappings(ctx context.Context, r *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.Queries.ListSubjectMappings(ctx, ListSubjectMappingsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappings := make([]*policy.SubjectMapping, len(list))
	for i, sm := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(sm.Metadata, metadata); err != nil {
			return nil, err
		}

		av := &policy.Value{}
		if err = unmarshalAttributeValue(sm.AttributeValue, av); err != nil {
			return nil, err
		}

		a := []*policy.Action{}
		if err = unmarshalActionsProto(sm.Actions, &a); err != nil {
			return nil, err
		}

		scs := policy.SubjectConditionSet{}
		if err = unmarshalSubjectConditionSet(sm.SubjectConditionSet, &scs); err != nil {
			return nil, err
		}

		mappings[i] = &policy.SubjectMapping{
			Id:                  sm.ID,
			Metadata:            metadata,
			AttributeValue:      av,
			SubjectConditionSet: &scs,
			Actions:             a,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &subjectmapping.ListSubjectMappingsResponse{
		SubjectMappings: mappings,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

// Mutates provided fields and returns the updated subject mapping
func (c PolicyDBClient) UpdateSubjectMapping(ctx context.Context, r *subjectmapping.UpdateSubjectMappingRequest) (*policy.SubjectMapping, error) {
	id := r.GetId()
	subjectConditionSetID := r.GetSubjectConditionSetId()
	actions := r.GetActions()
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetSubjectMapping(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	var actionsJSON []byte
	if actions != nil {
		actionsJSON, err = marshalActionsProto(actions)
		if err != nil {
			return nil, err
		}
	}

	count, err := c.Queries.UpdateSubjectMapping(ctx, UpdateSubjectMappingParams{
		ID:                    id,
		Actions:               actionsJSON,
		Metadata:              metadataJSON,
		SubjectConditionSetID: pgtypeUUID(subjectConditionSetID),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectMapping{
		Id:       id,
		Actions:  actions,
		Metadata: metadata,
		SubjectConditionSet: &policy.SubjectConditionSet{
			Id: subjectConditionSetID,
		},
	}, nil
}

// Deletes specified subject mapping and returns the id of the deleted
func (c PolicyDBClient) DeleteSubjectMapping(ctx context.Context, id string) (*policy.SubjectMapping, error) {
	count, err := c.Queries.DeleteSubjectMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.SubjectMapping{
		Id: id,
	}, nil
}

// GetMatchedSubjectMappings liberally returns a list of SubjectMappings based on the provided SubjectProperties.
// The SubjectMappings are returned if an external selector field matches.
//
// NOTE: Any matched SubjectMappings cannot entitle without resolution of the Condition Sets returned. Each contains
// logic that must be applied to a subject Entity Representation to assure entitlement.
func (c PolicyDBClient) GetMatchedSubjectMappings(ctx context.Context, properties []*policy.SubjectProperty) ([]*policy.SubjectMapping, error) {
	selectors := []string{}
	for _, sp := range properties {
		selectors = append(selectors, sp.GetExternalSelectorValue())
	}
	list, err := c.Queries.MatchSubjectMappings(ctx, selectors)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappings := make([]*policy.SubjectMapping, len(list))
	for i, sm := range list {
		av := &policy.Value{}
		if err = unmarshalAttributeValue(sm.AttributeValue, av); err != nil {
			return nil, err
		}

		a := []*policy.Action{}
		if err = unmarshalActionsProto(sm.Actions, &a); err != nil {
			return nil, err
		}

		scs := &policy.SubjectConditionSet{}
		if err = unmarshalSubjectConditionSet(sm.SubjectConditionSet, scs); err != nil {
			return nil, err
		}

		mappings[i] = &policy.SubjectMapping{
			Id:                  sm.ID,
			AttributeValue:      av,
			SubjectConditionSet: scs,
			Actions:             a,
		}
	}

	return mappings, nil
}
