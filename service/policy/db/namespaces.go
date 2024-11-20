package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (c PolicyDBClient) GetNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	ns, err := c.Queries.GetNamespace(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(ns.Metadata, metadata); err != nil {
		return nil, err
	}

	var grants []*policy.KeyAccessServer
	if ns.Grants != nil {
		grants, err = db.KeyAccessServerProtoJSON(ns.Grants)
		if err != nil {
			c.logger.Error("could not unmarshal grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	return &policy.Namespace{
		Id:       id,
		Name:     ns.Name,
		Active:   &wrapperspb.BoolValue{Value: ns.Active},
		Grants:   grants,
		Metadata: metadata,
		Fqn:      ns.Fqn.String,
	}, nil
}

func (c PolicyDBClient) ListNamespaces(ctx context.Context, r *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	active := pgtype.Bool{
		Valid: false,
	}
	state := getDBStateTypeTransformedEnum(r.GetState())
	if state != stateAny {
		active = pgtypeBool(state == stateActive)
	}

	list, err := c.Queries.ListNamespaces(ctx, ListNamespacesParams{
		Active: active,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	nsList := make([]*policy.Namespace, len(list))

	for i, ns := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(ns.Metadata, metadata); err != nil {
			return nil, err
		}

		nsList[i] = &policy.Namespace{
			Id:       ns.ID,
			Name:     ns.Name,
			Active:   &wrapperspb.BoolValue{Value: ns.Active},
			Metadata: metadata,
			Fqn:      ns.Fqn.String,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &namespaces.ListNamespacesResponse{
		Namespaces: nsList,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

// Loads all namespaces into memory by making iterative db roundtrip requests of defaultObjectListAllLimit size
func (c PolicyDBClient) ListAllNamespaces(ctx context.Context) ([]*policy.Namespace, error) {
	var nextOffset int32
	nsList := make([]*policy.Namespace, 0)

	for {
		listed, err := c.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			Pagination: &policy.PageRequest{
				Limit:  c.listCfg.limitMax,
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list all namespaces: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		nsList = append(nsList, listed.GetNamespaces()...)

		// offset becomes zero when list is exhausted
		if nextOffset <= 0 {
			break
		}
	}
	return nsList, nil
}

func (c PolicyDBClient) CreateNamespace(ctx context.Context, r *namespaces.CreateNamespaceRequest) (*policy.Namespace, error) {
	name := strings.ToLower(r.GetName())
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateNamespace(ctx, CreateNamespaceParams{
		Name:     name,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update FQN
	_, err = c.Queries.UpsertAttributeNamespaceFqn(ctx, createdID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetNamespace(ctx, createdID)
}

func (c PolicyDBClient) UpdateNamespace(ctx context.Context, id string, r *namespaces.UpdateNamespaceRequest) (*policy.Namespace, error) {
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		n, err := c.GetNamespace(ctx, id)
		if err != nil {
			return nil, err
		}
		if n.GetMetadata() == nil {
			return nil, nil //nolint:nilnil // no metadata does not mean no error
		}
		return n.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.UpdateNamespace(ctx, UpdateNamespaceParams{
		ID:       id,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id:       id,
		Metadata: metadata,
	}, nil
}

/*
UNSAFE OPERATIONS
*/
func (c PolicyDBClient) UnsafeUpdateNamespace(ctx context.Context, id string, name string) (*policy.Namespace, error) {
	name = strings.ToLower(name)

	count, err := c.Queries.UpdateNamespace(ctx, UpdateNamespaceParams{
		ID:   id,
		Name: pgtypeText(name),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// Update all FQNs that may contain the namespace name
	_, err = c.Queries.UpsertAttributeNamespaceFqn(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetNamespace(ctx, id)
}

func (c PolicyDBClient) DeactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	attrs, err := c.GetAttributesByNamespace(ctx, id)
	if err != nil {
		return nil, err
	}

	allAttrsDeactivated := true
	for _, attr := range attrs {
		if attr.GetActive().GetValue() {
			allAttrsDeactivated = false
			break
		}
	}

	if !allAttrsDeactivated {
		c.logger.Warn("deactivating the namespace with existing attributes can affect access to related data. Please be aware and proceed accordingly.")
	}

	count, err := c.Queries.UpdateNamespace(ctx, UpdateNamespaceParams{
		ID:     id,
		Active: pgtypeBool(false),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: false},
	}, nil
}

func (c PolicyDBClient) UnsafeReactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	attrs, err := c.GetAttributesByNamespace(ctx, id)
	if err != nil {
		return nil, err
	}

	if len(attrs) > 0 {
		c.logger.Warn("reactivating the namespace with existing attributes can affect access to related data. Please be aware and proceed accordingly.")
	}

	count, err := c.Queries.UpdateNamespace(ctx, UpdateNamespaceParams{
		ID:     id,
		Active: pgtypeBool(true),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: true},
	}, nil
}

func (c PolicyDBClient) UnsafeDeleteNamespace(ctx context.Context, existing *policy.Namespace, fqn string) (*policy.Namespace, error) {
	if existing == nil {
		return nil, fmt.Errorf("namespace not found: %w", db.ErrNotFound)
	}

	if existing.GetFqn() != fqn {
		return nil, fmt.Errorf("fqn mismatch: %w", db.ErrNotFound)
	}

	id := existing.GetId()

	count, err := c.Queries.DeleteNamespace(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id: id,
	}, nil
}

func (c PolicyDBClient) AssignKeyAccessServerToNamespace(ctx context.Context, k *namespaces.NamespaceKeyAccessServer) (*namespaces.NamespaceKeyAccessServer, error) {
	_, err := c.Queries.AssignKeyAccessServerToNamespace(ctx, AssignKeyAccessServerToNamespaceParams{
		NamespaceID:       k.GetNamespaceId(),
		KeyAccessServerID: k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}

func (c PolicyDBClient) RemoveKeyAccessServerFromNamespace(ctx context.Context, k *namespaces.NamespaceKeyAccessServer) (*namespaces.NamespaceKeyAccessServer, error) {
	count, err := c.Queries.RemoveKeyAccessServerFromNamespace(ctx, RemoveKeyAccessServerFromNamespaceParams{
		NamespaceID:       k.GetNamespaceId(),
		KeyAccessServerID: k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return k, nil
}
