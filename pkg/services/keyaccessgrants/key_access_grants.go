package keyaccessgrants

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/gen/common"
	kag "github.com/opentdf/opentdf-v2-poc/gen/key_access_grants"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type KeyAccessGrants struct {
	kag.UnimplementedKeyAccessGrantsServiceServer
	dbClient *db.Client
}

func NewKeyAccessGrantsServer(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	kagSvc := &KeyAccessGrants{
		dbClient: dbClient,
	}
	kag.RegisterKeyAccessGrantsServiceServer(grpcServer, kagSvc)

	err := kag.RegisterKeyAccessGrantsServiceHandlerServer(context.Background(), mux, kagSvc)
	if err != nil {
		return fmt.Errorf("failed to register key access grants service handler: %w", err)
	}
	return nil
}

func (s KeyAccessGrants) CreateKeyAccessGrants(ctx context.Context,
	req *kag.CreateKeyAccessGrantsRequest) (*kag.CreateKeyAccessGrantsResponse, error) {
	slog.Debug("creating key access grant")

	// Set the version of the resource to 1 on create
	req.Grants.Descriptor_.Version = 1

	resource, err := protojson.Marshal(req.Grants)
	if err != nil {
		return &kag.CreateKeyAccessGrantsResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.CreateResource(ctx, req.Grants.Descriptor_, resource)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return &kag.CreateKeyAccessGrantsResponse{}, status.Error(codes.Internal,
			fmt.Sprintf("%v: %v", services.ErrCreatingResource, err))
	}

	return &kag.CreateKeyAccessGrantsResponse{}, nil
}

func (s KeyAccessGrants) ListKeyAccessGrants(ctx context.Context,
	req *kag.ListKeyAccessGrantsRequest) (*kag.ListKeyAccessGrantsResponse, error) {
	grants := &kag.ListKeyAccessGrantsResponse{}

	rows, err := s.dbClient.ListResources(
		ctx,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return grants, status.Error(codes.Internal, services.ErrListingResource)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id     int32
			grant  = new(kag.KeyAccessGrants)
			bGrant []byte
		)
		err = rows.Scan(&id, &bGrant)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return grants, status.Error(codes.Internal, services.ErrListingResource)
		}

		err = protojson.Unmarshal(bGrant, grant)
		if err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return grants, status.Error(codes.Internal, services.ErrListingResource)
		}

		grant.Descriptor_.Id = id
		grants.Grants = append(grants.Grants, grant)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return grants, status.Error(codes.Internal, services.ErrListingResource)
	}

	if err := rows.Err(); err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return grants, status.Error(codes.Internal, services.ErrListingResource)
	}

	return grants, nil
}

func (s KeyAccessGrants) GetKeyAccessGrant(ctx context.Context,
	req *kag.GetKeyAccessGrantRequest) (*kag.GetKeyAccessGrantResponse, error) {
	var (
		grant = &kag.GetKeyAccessGrantResponse{
			Grants: new(kag.KeyAccessGrants),
		}
		id     int32
		bGrant []byte
	)

	row, err := s.dbClient.GetResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
	)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return grant, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = row.Scan(&id, &bGrant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info(services.ErrNotFound, slog.Int("id", int(req.Id)))
			return grant, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return grant, status.Error(codes.Internal, services.ErrGettingResource)
	}

	err = protojson.Unmarshal(bGrant, grant.Grants)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return grant, status.Error(codes.Internal, services.ErrGettingResource)
	}

	grant.Grants.Descriptor_.Id = id

	return grant, nil
}

func (s KeyAccessGrants) UpdateKeyAccessGrants(ctx context.Context,
	req *kag.UpdateKeyAccessGrantsRequest) (*kag.UpdateKeyAccessGrantsResponse, error) {
	resource, err := protojson.Marshal(req.Grants)
	if err != nil {
		return &kag.UpdateKeyAccessGrantsResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	err = s.dbClient.UpdateResource(
		ctx,
		req.Grants.Descriptor_,
		resource,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
	)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return &kag.UpdateKeyAccessGrantsResponse{},
			status.Error(codes.Internal, services.ErrUpdatingResource)
	}
	return &kag.UpdateKeyAccessGrantsResponse{}, nil
}

func (s KeyAccessGrants) DeleteKeyAccessGrants(ctx context.Context,
	req *kag.DeleteKeyAccessGrantsRequest) (*kag.DeleteKeyAccessGrantsResponse, error) {
	if err := s.dbClient.DeleteResource(
		ctx,
		req.Id,
		common.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
	); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return &kag.DeleteKeyAccessGrantsResponse{},
			status.Error(codes.Internal, services.ErrDeletingResource)
	}
	return &kag.DeleteKeyAccessGrantsResponse{}, nil
}
