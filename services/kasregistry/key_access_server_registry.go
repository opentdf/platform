package kasregistry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	kasr "github.com/opentdf/opentdf-v2-poc/sdk/kasregistry"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
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
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("keyAccessServer", req.KeyAccessServer.String()))
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
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
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
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("id", req.Id))
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
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("keyAccessServer", req.KeyAccessServer.String()))
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
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}
	return &kasr.DeleteKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}, nil
}
