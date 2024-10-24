package kasregistry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"

	policydb "github.com/opentdf/platform/service/policy/db"
)

type KeyAccessServerRegistry struct {
	kasr.UnimplementedKeyAccessServerRegistryServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &kasr.KeyAccessServerRegistryService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &KeyAccessServerRegistry{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger),
					logger:   srp.Logger,
					config:   policyconfig.GetSharedPolicyConfig(srp),
				}, func(ctx context.Context, mux *runtime.ServeMux, s any) error {
					srv, ok := s.(kasr.KeyAccessServerRegistryServiceServer)
					if !ok {
						return fmt.Errorf("argument is not of type kasr.KeyAccessServerRegistryServiceServer")
					}
					return kasr.RegisterKeyAccessServerRegistryServiceHandlerServer(ctx, mux, srv)
				}
		},
	}
}

func (s KeyAccessServerRegistry) CreateKeyAccessServer(ctx context.Context,
	req *kasr.CreateKeyAccessServerRequest,
) (*kasr.CreateKeyAccessServerResponse, error) {
	s.logger.Debug("creating key access server")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasRegistry,
	}

	ks, err := s.dbClient.CreateKeyAccessServer(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyAccessServer", req.String()))
	}

	auditParams.ObjectID = ks.GetId()
	auditParams.Original = ks
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &kasr.CreateKeyAccessServerResponse{
		KeyAccessServer: ks,
	}, nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServers(ctx context.Context,
	r *kasr.ListKeyAccessServersRequest,
) (*kasr.ListKeyAccessServersResponse, error) {
	maxLimit := s.config.ListRequestLimitMax
	if maxLimit > 0 && r.GetPagination().GetLimit() > int32(maxLimit) {
		return nil, db.StatusifyError(db.ErrListLimitTooLarge, db.ErrTextListLimitTooLarge)
	}

	rsp, err := s.dbClient.ListKeyAccessServers(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
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
	kasID := req.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKasRegistry,
		ObjectID:   kasID,
	}

	original, err := s.dbClient.GetKeyAccessServer(ctx, kasID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", kasID))
	}

	updated, err := s.dbClient.UpdateKeyAccessServer(ctx, kasID, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", kasID), slog.String("keyAccessServer", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &kasr.UpdateKeyAccessServerResponse{
		KeyAccessServer: &policy.KeyAccessServer{
			Id: kasID,
		},
	}, nil
}

func (s KeyAccessServerRegistry) DeleteKeyAccessServer(ctx context.Context,
	req *kasr.DeleteKeyAccessServerRequest,
) (*kasr.DeleteKeyAccessServerResponse, error) {
	kasID := req.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasRegistry,
		ObjectID:   kasID,
	}

	_, err := s.dbClient.DeleteKeyAccessServer(ctx, req.GetId())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return &kasr.DeleteKeyAccessServerResponse{
		KeyAccessServer: &policy.KeyAccessServer{
			Id: kasID,
		},
	}, nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServerGrants(ctx context.Context,
	req *kasr.ListKeyAccessServerGrantsRequest,
) (*kasr.ListKeyAccessServerGrantsResponse, error) {
	maxLimit := s.config.ListRequestLimitMax
	if maxLimit > 0 && req.GetPagination().GetLimit() > int32(maxLimit) {
		return nil, db.StatusifyError(db.ErrListLimitTooLarge, db.ErrTextListLimitTooLarge)
	}

	rsp, err := s.dbClient.ListKeyAccessServerGrants(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	return rsp, nil
}
