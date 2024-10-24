package namespaces

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NamespacesService struct { //nolint:revive // NamespacesService is a valid name
	namespaces.UnimplementedNamespaceServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &namespaces.NamespaceService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			ns := &NamespacesService{
				dbClient: policydb.NewClient(srp.DBClient, srp.Logger),
				logger:   srp.Logger,
				config:   policyconfig.GetSharedPolicyConfig(srp),
			}
			if err := srp.RegisterReadinessCheck("policy", ns.IsReady); err != nil {
				srp.Logger.Error("failed to register policy readiness check", slog.String("error", err.Error()))
			}

			return ns, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				nsServer, ok := server.(namespaces.NamespaceServiceServer)
				if !ok {
					return fmt.Errorf("failed to assert server as namespaces.NamespaceServiceServer")
				}
				return namespaces.RegisterNamespaceServiceHandlerServer(ctx, mux, nsServer)
			}
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

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	ns.logger.Debug("listing namespaces", slog.String("state", req.GetState().String()))

	maxLimit := ns.config.ListRequestLimitMax
	if maxLimit > 0 && req.GetPagination().GetLimit() > int32(maxLimit) {
		return nil, db.StatusifyError(db.ErrListLimitTooLarge, db.ErrTextListLimitTooLarge)
	}

	rsp, err := ns.dbClient.ListNamespaces(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	ns.logger.Debug("listed namespaces")

	return rsp, nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest) (*namespaces.GetNamespaceResponse, error) {
	ns.logger.Debug("getting namespace", slog.String("id", req.GetId()))

	rsp := &namespaces.GetNamespaceResponse{}

	namespace, err := ns.dbClient.GetNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, "id", req.GetId())
	}

	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error) {
	ns.logger.Debug("creating new namespace", slog.String("name", req.GetName()))

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeNamespace,
	}
	rsp := &namespaces.CreateNamespaceResponse{}

	n, err := ns.dbClient.CreateNamespace(ctx, req)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("name", req.GetName()))
	}

	auditParams.ObjectID = n.GetId()
	auditParams.Original = n
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	ns.logger.Debug("created new namespace", slog.String("name", req.GetName()))
	rsp.Namespace = n

	return rsp, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error) {
	namespaceID := req.GetId()
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

	updated, err := ns.dbClient.UpdateNamespace(ctx, namespaceID, req)
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
	return rsp, nil
}

func (ns NamespacesService) DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest) (*namespaces.DeactivateNamespaceResponse, error) {
	namespaceID := req.GetId()

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

	return rsp, nil
}

func (ns NamespacesService) AssignKeyAccessServerToNamespace(ctx context.Context, req *namespaces.AssignKeyAccessServerToNamespaceRequest) (*namespaces.AssignKeyAccessServerToNamespaceResponse, error) {
	grant := req.GetNamespaceKeyAccessServer()
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

	return &namespaces.AssignKeyAccessServerToNamespaceResponse{
		NamespaceKeyAccessServer: namespaceKas,
	}, nil
}

func (ns NamespacesService) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *namespaces.RemoveKeyAccessServerFromNamespaceRequest) (*namespaces.RemoveKeyAccessServerFromNamespaceResponse, error) {
	grant := req.GetNamespaceKeyAccessServer()
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

	return &namespaces.RemoveKeyAccessServerFromNamespaceResponse{
		NamespaceKeyAccessServer: namespaceKas,
	}, nil
}
