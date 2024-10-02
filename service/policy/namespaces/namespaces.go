package namespaces

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NamespacesService struct { //nolint:revive // NamespacesService is a valid name
	namespaces.UnimplementedNamespaceServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration(ns string, dbregister serviceregistry.DBRegister) *serviceregistry.Service[namespacesconnect.NamespaceServiceHandler] {
	return &serviceregistry.Service[namespacesconnect.NamespaceServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[namespacesconnect.NamespaceServiceHandler]{
			Namespace:   ns,
			DB:          dbregister,
			ServiceDesc: &namespaces.NamespaceService_ServiceDesc,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (namespacesconnect.NamespaceServiceHandler, serviceregistry.HandlerServer) {
				ns := &NamespacesService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}

				if err := srp.RegisterReadinessCheck("policy", ns.IsReady); err != nil {
					srp.Logger.Error("failed to register policy readiness check", slog.String("error", err.Error()))
				}

				return ns, func(ctx context.Context, mux *http.ServeMux, server any) {}
			},
			ConnectRPCFunc: namespacesconnect.NewNamespaceServiceHandler,
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
	r := req.Msg
	state := policydb.GetDBStateTypeTransformedEnum(r.GetState())
	ns.logger.Debug("listing namespaces", slog.String("state", state))

	rsp := &namespaces.ListNamespacesResponse{}
	list, err := ns.dbClient.ListNamespaces(ctx, state)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	ns.logger.Debug("listed namespaces")
	rsp.Namespaces = list

	return &connect.Response[namespaces.ListNamespacesResponse]{Msg: rsp}, nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error) {
	r := req.Msg
	ns.logger.Debug("getting namespace", slog.String("id", r.GetId()))

	rsp := &namespaces.GetNamespaceResponse{}

	namespace, err := ns.dbClient.GetNamespace(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, "id", r.GetId())
	}

	rsp.Namespace = namespace

	return &connect.Response[namespaces.GetNamespaceResponse]{Msg: rsp}, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error) {
	r := req.Msg
	ns.logger.Debug("creating new namespace", slog.String("name", r.GetName()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeNamespace,
	}
	rsp := &namespaces.CreateNamespaceResponse{}

	n, err := ns.dbClient.CreateNamespace(ctx, r)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("name", r.GetName()))
	}

	auditParams.ObjectID = n.GetId()
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	ns.logger.Debug("created new namespace", slog.String("name", r.GetName()))
	rsp.Namespace = n

	return &connect.Response[namespaces.CreateNamespaceResponse]{Msg: rsp}, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error) {
	r := req.Msg
	namespaceID := r.GetId()
	ns.logger.Debug("updating namespace", slog.String("name", namespaceID))
	rsp := &namespaces.UpdateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   namespaceID,
	}

	originalNamespace, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updatedNamespace, err := ns.dbClient.UpdateNamespace(ctx, namespaceID, r)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = originalNamespace
	auditParams.Updated = &policy.Namespace{
		Id:       originalNamespace.GetId(),
		Name:     originalNamespace.GetName(),
		Active:   originalNamespace.GetActive(),
		Metadata: updatedNamespace.GetMetadata(),
		Fqn:      originalNamespace.GetFqn(),
		Grants:   originalNamespace.GetGrants(),
	}

	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.Debug("updated namespace", slog.String("id", namespaceID))

	rsp.Namespace = &policy.Namespace{
		Id: namespaceID,
	}
	return &connect.Response[namespaces.UpdateNamespaceResponse]{Msg: rsp}, nil
}

func (ns NamespacesService) DeactivateNamespace(ctx context.Context, req *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error) {
	r := req.Msg
	namespaceID := r.GetId()

	ns.logger.Debug("deactivating namespace", slog.String("id", namespaceID))
	rsp := &namespaces.DeactivateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   namespaceID,
	}

	originalNamespace, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updatedNamespace, err := ns.dbClient.DeactivateNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = originalNamespace
	auditParams.Updated = &policy.Namespace{
		Id:       originalNamespace.GetId(),
		Name:     originalNamespace.GetName(),
		Active:   updatedNamespace.GetActive(),
		Metadata: originalNamespace.GetMetadata(),
		Fqn:      originalNamespace.GetFqn(),
		Grants:   originalNamespace.GetGrants(),
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.Debug("soft-deleted namespace", slog.String("id", namespaceID))

	return &connect.Response[namespaces.DeactivateNamespaceResponse]{Msg: rsp}, nil
}

func (ns NamespacesService) AssignKeyAccessServerToNamespace(ctx context.Context, req *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error) {
	r := req.Msg
	grant := r.GetNamespaceKeyAccessServer()
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
	rsp := &namespaces.AssignKeyAccessServerToNamespaceResponse{
		NamespaceKeyAccessServer: namespaceKas,
	}
	return &connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse]{Msg: rsp}, nil
}

func (ns NamespacesService) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error) {
	r := req.Msg
	grant := r.GetNamespaceKeyAccessServer()
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
	rsp := &namespaces.RemoveKeyAccessServerFromNamespaceResponse{
		NamespaceKeyAccessServer: namespaceKas,
	}
	return &connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse]{Msg: rsp}, nil
}
