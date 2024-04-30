package kasregistry

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type KeyAccessServerRegistry struct {
	kasr.UnimplementedKeyAccessServerRegistryServiceServer
	dbClient policydb.PolicyDBClient
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &kasr.KeyAccessServerRegistryService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &KeyAccessServerRegistry{dbClient: policydb.NewClient(srp.DBClient)}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
				return kasr.RegisterKeyAccessServerRegistryServiceHandlerServer(ctx, mux, s.(kasr.KeyAccessServerRegistryServiceServer))
			}
		},
	}
}

func (s KeyAccessServerRegistry) CreateKeyAccessServer(ctx context.Context,
	req *kasr.CreateKeyAccessServerRequest,
) (*kasr.CreateKeyAccessServerResponse, error) {
	slog.Debug("creating key access server")

	ks, err := s.dbClient.CreateKeyAccessServer(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyAccessServer", req.String()))
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
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return &kasr.ListKeyAccessServersResponse{
		KeyAccessServers: keyAccessServers,
	}, nil
}

func (s KeyAccessServerRegistry) GetKeyAccessServer(ctx context.Context,
	req *kasr.GetKeyAccessServerRequest,
) (*kasr.GetKeyAccessServerResponse, error) {
	keyAccessServer, err := s.dbClient.GetKeyAccessServer(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	return &kasr.GetKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}, nil
}

func (s KeyAccessServerRegistry) UpdateKeyAccessServer(ctx context.Context,
	req *kasr.UpdateKeyAccessServerRequest,
) (*kasr.UpdateKeyAccessServerResponse, error) {
	k, err := s.dbClient.UpdateKeyAccessServer(ctx, req.GetId(), req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("keyAccessServer", req.String()))
	}
	return &kasr.UpdateKeyAccessServerResponse{
		KeyAccessServer: k,
	}, nil
}

func (s KeyAccessServerRegistry) DeleteKeyAccessServer(ctx context.Context,
	req *kasr.DeleteKeyAccessServerRequest,
) (*kasr.DeleteKeyAccessServerResponse, error) {
	keyAccessServer, err := s.dbClient.DeleteKeyAccessServer(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}
	return &kasr.DeleteKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}, nil
}
