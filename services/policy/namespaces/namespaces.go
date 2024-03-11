package namespaces

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/services"
	policydb "github.com/opentdf/platform/services/policy/db"
)

type NamespacesService struct {
	namespaces.UnimplementedNamespaceServiceServer
	dbClient *policydb.PolicyDbClient
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
	state := services.GetDbStateTypeTransformedEnum(req.State)
	slog.Debug("listing namespaces", slog.String("state", state))

	rsp := &namespaces.ListNamespacesResponse{}
	list, err := ns.dbClient.ListNamespaces(ctx, state)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}

	slog.Debug("listed namespaces")
	rsp.Namespaces = list

	return rsp, nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest) (*namespaces.GetNamespaceResponse, error) {
	slog.Debug("getting namespace", slog.String("id", req.Id))

	rsp := &namespaces.GetNamespaceResponse{}

	namespace, err := ns.dbClient.GetNamespace(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, "id", req.Id)
	}

	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error) {
	slog.Debug("creating new namespace", slog.String("name", req.Name))
	rsp := &namespaces.CreateNamespaceResponse{}

	n, err := ns.dbClient.CreateNamespace(ctx, req)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("name", req.Name))
	}

	slog.Debug("created new namespace", slog.String("name", req.Name))
	rsp.Namespace = n

	return rsp, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error) {
	slog.Debug("updating namespace", slog.String("name", req.Id))
	rsp := &namespaces.UpdateNamespaceResponse{}

	namespace, err := ns.dbClient.UpdateNamespace(ctx, req.Id, req)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id))
	}

	slog.Debug("updated namespace", slog.String("id", req.Id))
	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) DeactivateNamespace(ctx context.Context, req *namespaces.DeactivateNamespaceRequest) (*namespaces.DeactivateNamespaceResponse, error) {
	slog.Debug("deactivating namespace", slog.String("id", req.Id))
	rsp := &namespaces.DeactivateNamespaceResponse{}

	if _, err := ns.dbClient.DeactivateNamespace(ctx, req.Id); err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}

	slog.Debug("soft-deleted namespace", slog.String("id", req.Id))
	return rsp, nil
}
