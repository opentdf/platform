package namespaces

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	namespace "github.com/opentdf/opentdf-v2-poc/protocol/go/policy/namespaces"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
)

type NamespacesService struct {
	namespace.UnimplementedNamespaceServiceServer
	dbClient *db.Client
}

func NewNamespacesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	ns := &NamespacesService{
		dbClient: dbClient,
	}
	namespace.RegisterNamespaceServiceServer(g, ns)
	err := namespace.RegisterNamespaceServiceHandlerServer(context.Background(), s, ns)
	if err != nil {
		return fmt.Errorf("failed to register namespace service handler: %w", err)
	}
	return nil
}

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *namespace.ListNamespacesRequest) (*namespace.ListNamespacesResponse, error) {
	slog.Debug("listing namespaces")

	rsp := &namespace.ListNamespacesResponse{}
	list, err := ns.dbClient.ListNamespaces(ctx)
	if err != nil {
		return nil, services.HandleError(err, services.ErrListRetrievalFailed)
	}

	slog.Debug("listed namespaces")
	rsp.Namespaces = list

	return rsp, nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *namespace.GetNamespaceRequest) (*namespace.GetNamespaceResponse, error) {
	slog.Debug("getting namespace", slog.String("id", req.Id))

	rsp := &namespace.GetNamespaceResponse{}

	namespace, err := ns.dbClient.GetNamespace(ctx, req.Id)
	if err != nil {
		return nil, services.HandleError(err, services.ErrGetRetrievalFailed, "id", req.Id)
	}

	slog.Debug("got namespace", slog.String("id", req.Id))
	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *namespace.CreateNamespaceRequest) (*namespace.CreateNamespaceResponse, error) {
	slog.Debug("creating new namespace", slog.String("name", req.Name))
	rsp := &namespace.CreateNamespaceResponse{}

	id, err := ns.dbClient.CreateNamespace(ctx, req.Name)
	if err != nil {
		return nil, services.HandleError(err, services.ErrCreationFailed, slog.String("name", req.Name))
	}

	slog.Debug("created new namespace", slog.String("name", req.Name))
	rsp.Namespace = &namespace.Namespace{
		Id: id,
		// TODO: are we responding with id only or the entire new namespace?
		// Name: req.Namespace.Name,
	}

	return rsp, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *namespace.UpdateNamespaceRequest) (*namespace.UpdateNamespaceResponse, error) {
	slog.Debug("updating namespace", slog.String("name", req.Name))
	rsp := &namespace.UpdateNamespaceResponse{}

	namespace, err := ns.dbClient.UpdateNamespace(ctx, req.Id, req.Name)
	if err != nil {
		return nil, services.HandleError(err, services.ErrUpdateFailed, slog.String("id", req.Id), slog.String("name", req.Name))
	}

	slog.Debug("updated namespace", slog.String("name", req.Name))
	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) DeleteNamespace(ctx context.Context, req *namespace.DeleteNamespaceRequest) (*namespace.DeleteNamespaceResponse, error) {
	slog.Debug("deleting namespace", slog.String("id", req.Id))
	rsp := &namespace.DeleteNamespaceResponse{}

	if _, err := ns.dbClient.DeleteNamespace(ctx, req.Id); err != nil {
		return nil, services.HandleError(err, services.ErrDeletionFailed, slog.String("id", req.Id))
	}

	slog.Debug("deleted namespace", slog.String("id", req.Id))
	return rsp, nil
}
