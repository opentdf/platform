package namespaces

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NamespacesService struct { //nolint:revive // NamespacesService is a valid name
	namespaces.UnimplementedNamespaceServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &namespaces.NamespaceService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			ns := &NamespacesService{dbClient: policydb.NewClient(srp.DBClient), logger: srp.Logger}

			if err := srp.RegisterReadinessCheck("policy", ns.IsReady); err != nil {
				slog.Error("failed to register policy readiness check", slog.String("error", err.Error()))
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
	slog.DebugContext(ctx, "checking readiness of namespaces service")
	if err := ns.dbClient.SQLDB.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	state := policydb.GetDBStateTypeTransformedEnum(req.GetState())
	ns.logger.Debug("listing namespaces", slog.String("state", state))

	rsp := &namespaces.ListNamespacesResponse{}
	list, err := ns.dbClient.ListNamespaces(ctx, state)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	ns.logger.Debug("listed namespaces")
	rsp.Namespaces = list

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

	originalNamespace, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updatedNamespace, err := ns.dbClient.UpdateNamespace(ctx, namespaceID, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = originalNamespace
	auditParams.Updated = updatedNamespace
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.Debug("updated namespace", slog.String("id", namespaceID))

	rsp.Namespace = updatedNamespace
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
	auditParams.Updated = updatedNamespace
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.Debug("soft-deleted namespace", slog.String("id", namespaceID))

	return rsp, nil
}
