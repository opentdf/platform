package kasregistry

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type KeyAccessServerRegistry struct {
	kasr.UnimplementedKeyAccessServerRegistryServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &kasr.KeyAccessServerRegistryService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			kr := &KeyAccessServerRegistry{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}
			return kr, func(ctx context.Context, mux *http.ServeMux, s any) {
				// interceptor := srp.OTDF.AuthN.ConnectUnaryServerInterceptor()
				interceptors := connect.WithInterceptors()
				path, handler := kasregistryconnect.NewKeyAccessServerRegistryServiceHandler(kr, interceptors)
				mux.Handle(path, handler)
			}
		},
	}
}

func (s KeyAccessServerRegistry) CreateKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.CreateKeyAccessServerRequest],
) (*connect.Response[kasr.CreateKeyAccessServerResponse], error) {
	r := req.Msg
	s.logger.Debug("creating key access server")

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasRegistry,
	}

	ks, err := s.dbClient.CreateKeyAccessServer(ctx, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("keyAccessServer", r.String()))
	}

	auditParams.ObjectID = ks.GetId()
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &kasr.CreateKeyAccessServerResponse{
		KeyAccessServer: ks,
	}
	return &connect.Response[kasr.CreateKeyAccessServerResponse]{Msg: rsp}, nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServers(ctx context.Context,
	_ *connect.Request[kasr.ListKeyAccessServersRequest],
) (*connect.Response[kasr.ListKeyAccessServersResponse], error) {
	keyAccessServers, err := s.dbClient.ListKeyAccessServers(ctx)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	rsp := &kasr.ListKeyAccessServersResponse{
		KeyAccessServers: keyAccessServers,
	}
	return &connect.Response[kasr.ListKeyAccessServersResponse]{Msg: rsp}, nil
}

func (s KeyAccessServerRegistry) GetKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.GetKeyAccessServerRequest],
) (*connect.Response[kasr.GetKeyAccessServerResponse], error) {
	r := req.Msg
	keyAccessServer, err := s.dbClient.GetKeyAccessServer(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}
	rsp := &kasr.GetKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}
	return &connect.Response[kasr.GetKeyAccessServerResponse]{Msg: rsp}, nil
}

func (s KeyAccessServerRegistry) UpdateKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.UpdateKeyAccessServerRequest],
) (*connect.Response[kasr.UpdateKeyAccessServerResponse], error) {
	r := req.Msg
	kasID := r.GetId()

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKasRegistry,
		ObjectID:   kasID,
	}

	originalKAS, err := s.dbClient.GetKeyAccessServer(ctx, kasID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", kasID))
	}

	item, err := s.dbClient.UpdateKeyAccessServer(ctx, kasID, r)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("keyAccessServer", r.String()))
	}

	// UpdateKeyAccessServer only returns the ID of the updated KAS, so we need to
	// fetch the updated KAS to compute the audit diff
	updatedKAS, err := s.dbClient.GetKeyAccessServer(ctx, kasID)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", kasID))
	}

	auditParams.Original = originalKAS
	auditParams.Updated = updatedKAS
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &kasr.UpdateKeyAccessServerResponse{
		KeyAccessServer: item,
	}
	return &connect.Response[kasr.UpdateKeyAccessServerResponse]{Msg: rsp}, nil
}

func (s KeyAccessServerRegistry) DeleteKeyAccessServer(ctx context.Context,
	req *connect.Request[kasr.DeleteKeyAccessServerRequest],
) (*connect.Response[kasr.DeleteKeyAccessServerResponse], error) {
	r := req.Msg
	kasID := r.GetId()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasRegistry,
		ObjectID:   kasID,
	}

	keyAccessServer, err := s.dbClient.DeleteKeyAccessServer(ctx, r.GetId())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", r.GetId()))
	}
	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	rsp := &kasr.DeleteKeyAccessServerResponse{
		KeyAccessServer: keyAccessServer,
	}
	return &connect.Response[kasr.DeleteKeyAccessServerResponse]{Msg: rsp}, nil
}

func (s KeyAccessServerRegistry) ListKeyAccessServerGrants(ctx context.Context,
	req *connect.Request[kasr.ListKeyAccessServerGrantsRequest],
) (*connect.Response[kasr.ListKeyAccessServerGrantsResponse], error) {
	r := req.Msg
	keyAccessServerGrants, err := s.dbClient.ListKeyAccessServerGrants(ctx, r.GetKasId(), r.GetKasUri())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}
	rsp := &kasr.ListKeyAccessServerGrantsResponse{
		Grants: keyAccessServerGrants,
	}
	return &connect.Response[kasr.ListKeyAccessServerGrantsResponse]{Msg: rsp}, nil
}
