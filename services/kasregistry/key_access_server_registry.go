package kasregistry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	kasr "github.com/opentdf/opentdf-v2-poc/sdk/kasregistry"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type KeyAccessServerRegistry struct {
	kasr.UnimplementedKeyAccessServerRegistryServiceServer
	dbClient *db.Client
}

func NewKeyAccessServerRegistryServer(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	kagSvc := &KeyAccessServerRegistry{
		dbClient: dbClient,
	}
	kasr.RegisterKeyAccessServerRegistryServiceServer(grpcServer, kagSvc)

	err := kasr.RegisterKeyAccessServerRegistryServiceHandlerServer(context.Background(), mux, kagSvc)
	if err != nil {
		return fmt.Errorf("failed to register key access server service handler: %w", err)
	}
	return nil
}

func (s KeyAccessServerRegistry) CreateKeyAccessServer(ctx context.Context,
	req *kasr.CreateKeyAccessServerRequest,
) (*kasr.CreateKeyAccessServerResponse, error) {
	slog.Debug("creating key access server")

	ks, err := s.dbClient.CreateKeyAccessServer(ctx, req.KeyAccessServer)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		slog.Error(services.ErrCreationFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("%v: %v", services.ErrCreationFailed, err))
	}

	return &kasr.CreateKeyAccessServerResponse{
		KeyAccessServer: ks,
	}, nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServers(ctx context.Context,
	req *kasr.ListKeyAccessServersRequest,
) (*kasr.ListKeyAccessServersResponse, error) {
	keyAccessServers, err := s.dbClient.ListKeyAccessServers(ctx)
	if err != nil {
		slog.Error(services.ErrListRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListRetrievalFailed)
	}

	return &kasr.ListKeyAccessServersResponse{
		KeyAccessServers: keyAccessServers,
	}, nil
}

func (s KeyAccessServerRegistry) GetKeyAccessServer(ctx context.Context,
	req *kasr.GetKeyAccessServerRequest,
) (*kasr.GetKeyAccessServerResponse, error) {
	keyAccessServer, err := s.dbClient.GetKeyAccessServer(ctx, req.Id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGetRetrievalFailed, slog.String("error", err.Error()), slog.String("id", req.Id))
		return nil, status.Error(codes.Internal, services.ErrGetRetrievalFailed)
	}

	return &kasr.GetKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}, nil
}

func (s KeyAccessServerRegistry) UpdateKeyAccessServer(ctx context.Context,
	req *kasr.UpdateKeyAccessServerRequest,
) (*kasr.UpdateKeyAccessServerResponse, error) {
	k, err := s.dbClient.UpdateKeyAccessServer(ctx, req.Id, req.KeyAccessServer)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("keyAccessServer", req.KeyAccessServer.String()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("keyAccessServer", req.KeyAccessServer.String()))
		return nil,
			status.Error(codes.Internal, services.ErrUpdateFailed)
	}
	return &kasr.UpdateKeyAccessServerResponse{
		KeyAccessServer: k,
	}, nil
}

func (s KeyAccessServerRegistry) DeleteKeyAccessServer(ctx context.Context,
	req *kasr.DeleteKeyAccessServerRequest,
) (*kasr.DeleteKeyAccessServerResponse, error) {
	keyAccessServer, err := s.dbClient.DeleteKeyAccessServer(ctx, req.Id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrDeletionFailed, slog.String("error", err.Error()), slog.String("id", req.Id))
		return nil,
			status.Error(codes.Internal, services.ErrDeletionFailed)
	}
	return &kasr.DeleteKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}, nil
}
