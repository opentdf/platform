package namespaces

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NamespacesService struct { //nolint:revive // NamespacesService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[namespacesconnect.NamespaceServiceHandler] {
	return &serviceregistry.Service[namespacesconnect.NamespaceServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[namespacesconnect.NamespaceServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &namespaces.NamespaceService_ServiceDesc,
			ConnectRPCFunc: namespacesconnect.NewNamespaceServiceHandler,
			GRPCGateayFunc: namespaces.RegisterNamespaceServiceHandlerFromEndpoint,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (namespacesconnect.NamespaceServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				ns := &NamespacesService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}

				if err := srp.RegisterReadinessCheck("policy", ns.IsReady); err != nil {
					srp.Logger.Error("failed to register policy readiness check", slog.String("error", err.Error()))
				}

				return ns, nil
			},
		},
	}
}

// IsReady checks if the service is ready to serve requests.
// Without a database connection, the service is not ready.
func (ns NamespacesService) IsReady(ctx context.Context) error {
	ns.logger.TraceContext(ctx, "checking readiness of namespaces service")
	if err := ns.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *connect.Request[namespaces.ListNamespacesRequest]) (*connect.Response[namespaces.ListNamespacesResponse], error) {
	state := req.Msg.GetState().String()
	ns.logger.Debug("listing namespaces", slog.String("state", state))

	rsp, err := ns.dbClient.ListNamespaces(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	ns.logger.Debug("listed namespaces")

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error) {
	ns.logger.Debug("getting namespace", slog.String("id", req.Msg.GetId()))

	rsp := &namespaces.GetNamespaceResponse{}

	namespace, err := ns.dbClient.GetNamespace(ctx, req.Msg.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, "id", req.Msg.GetId())
	}

	rsp.Namespace = namespace

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error) {
	ns.logger.Debug("creating new namespace", slog.String("name", req.Msg.GetName()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeNamespace,
	}
	rsp := &namespaces.CreateNamespaceResponse{}

	n, err := ns.dbClient.CreateNamespace(ctx, req.Msg)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("name", req.Msg.GetName()))
	}

	auditParams.ObjectID = n.GetId()
	auditParams.Original = n
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	ns.logger.Debug("created new namespace", slog.String("name", req.Msg.GetName()))
	rsp.Namespace = n

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error) {
	namespaceID := req.Msg.GetId()
	ns.logger.Debug("updating namespace", slog.String("name", namespaceID))
	rsp := &namespaces.UpdateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   namespaceID,
	}

	original, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updated, err := ns.dbClient.UpdateNamespace(ctx, namespaceID, req.Msg)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.Debug("updated namespace", slog.String("id", namespaceID))

	rsp.Namespace = &policy.Namespace{
		Id: namespaceID,
	}
	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) DeactivateNamespace(ctx context.Context, req *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error) {
	namespaceID := req.Msg.GetId()

	ns.logger.Debug("deactivating namespace", slog.String("id", namespaceID))
	rsp := &namespaces.DeactivateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   namespaceID,
	}

	original, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updated, err := ns.dbClient.DeactivateNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.Debug("soft-deleted namespace", slog.String("id", namespaceID))

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) AssignKeyAccessServerToNamespace(ctx context.Context, req *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error) {
	rsp := &namespaces.AssignKeyAccessServerToNamespaceResponse{}

	grant := req.Msg.GetNamespaceKeyAccessServer()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeNamespaceAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", grant.GetNamespaceId(), grant.GetKeyAccessServerId()),
	}

	namespaceKas, err := ns.dbClient.AssignKeyAccessServerToNamespace(ctx, grant)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("namespaceKas", grant.String()))
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.NamespaceKeyAccessServer = namespaceKas

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error) {
	rsp := &namespaces.RemoveKeyAccessServerFromNamespaceResponse{}

	grant := req.Msg.GetNamespaceKeyAccessServer()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeNamespaceAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", grant.GetNamespaceId(), grant.GetKeyAccessServerId()),
	}

	namespaceKas, err := ns.dbClient.RemoveKeyAccessServerFromNamespace(ctx, grant)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("namespaceKas", grant.String()))
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.NamespaceKeyAccessServer = namespaceKas

	return connect.NewResponse(rsp), nil
}
