package namespaces

import (
	"context"
	"log/slog"

	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/namespaces"
	"github.com/arkavo-org/opentdf-platform/service/internal/db"
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	policydb "github.com/arkavo-org/opentdf-platform/service/policy/db"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type NamespacesService struct {
	namespaces.UnimplementedNamespaceServiceServer
	dbClient *policydb.PolicyDBClient
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "policy",
		ServiceDesc: &namespaces.NamespaceService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &NamespacesService{dbClient: policydb.NewClient(*srp.DBClient)}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				return namespaces.RegisterNamespaceServiceHandlerServer(ctx, mux, server.(namespaces.NamespaceServiceServer))
			}
		},
	}
}

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	state := policydb.GetDBStateTypeTransformedEnum(req.GetState())
	slog.Debug("listing namespaces", slog.String("state", state))

	rsp := &namespaces.ListNamespacesResponse{}
	list, err := ns.dbClient.ListNamespaces(ctx, state)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextListRetrievalFailed)
	}

	slog.Debug("listed namespaces")
	rsp.Namespaces = list

	return rsp, nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest) (*namespaces.GetNamespaceResponse, error) {
	slog.Debug("getting namespace", slog.String("id", req.GetId()))

	rsp := &namespaces.GetNamespaceResponse{}

	namespace, err := ns.dbClient.GetNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, "id", req.GetId())
	}

	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error) {
	slog.Debug("creating new namespace", slog.String("name", req.GetName()))
	rsp := &namespaces.CreateNamespaceResponse{}

	n, err := ns.dbClient.CreateNamespace(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextCreationFailed, slog.String("name", req.GetName()))
	}

	slog.Debug("created new namespace", slog.String("name", req.GetName()))
	rsp.Namespace = n

	return rsp, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error) {
	slog.Debug("updating namespace", slog.String("name", req.GetId()))
	rsp := &namespaces.UpdateNamespaceResponse{}

	namespace, err := ns.dbClient.UpdateNamespace(ctx, req.GetId(), req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	}

	slog.Debug("updated namespace", slog.String("id", req.GetId()))
	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest) (*namespaces.DeactivateNamespaceResponse, error) {
	slog.Debug("deactivating namespace", slog.String("id", req.GetId()))
	rsp := &namespaces.DeactivateNamespaceResponse{}

	if _, err := ns.dbClient.DeactivateNamespace(ctx, req.GetId()); err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	slog.Debug("soft-deleted namespace", slog.String("id", req.GetId()))
	return rsp, nil
}
