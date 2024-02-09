package namespaces

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/namespaces"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type NamespacesService struct {
	namespaces.UnimplementedNamespaceServiceServer
	dbClient *db.Client
}

func NewNamespacesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	ns := &NamespacesService{
		dbClient: dbClient,
	}
	namespaces.RegisterNamespaceServiceServer(g, ns)
	err := namespaces.RegisterNamespaceServiceHandlerServer(context.Background(), s, ns)
	if err != nil {
		return fmt.Errorf("failed to register namespace service handler: %w", err)
	}
	return nil
}

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	slog.Debug("listing namespaces")

	rsp := &namespaces.ListNamespacesResponse{}
	list, err := ns.dbClient.ListNamespaces(ctx)
	if err != nil {
		slog.Error(services.ErrListRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListRetrievalFailed)
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
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("namespaceId", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrGetRetrievalFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGetRetrievalFailed)
	}

	slog.Debug("got namespace", slog.String("id", req.Id))
	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error) {
	slog.Debug("creating new namespace", slog.String("name", req.Name))
	rsp := &namespaces.CreateNamespaceResponse{}

	id, err := ns.dbClient.CreateNamespace(ctx, req.Name)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		slog.Error(services.ErrCreationFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreationFailed)
	}

	slog.Debug("created new namespace", slog.String("name", req.Name))
	rsp.Namespace = &namespaces.Namespace{
		Id: id,
		// TODO: are we responding with id only or the entire new namespace?
		// Name: req.Namespace.Name,
	}

	return rsp, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error) {
	slog.Debug("updating namespace", slog.String("name", req.Name))
	rsp := &namespaces.UpdateNamespaceResponse{}

	namespace, err := ns.dbClient.UpdateNamespace(ctx, req.Id, req.Name)
	if err != nil {
		if errors.Is(err, db.ErrUniqueConstraintViolation) {
			slog.Error(services.ErrConflict, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.AlreadyExists, services.ErrConflict)
		}
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()), slog.String("id", req.Id))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrUpdateFailed, slog.String("error", err.Error()), slog.String("id", req.Id), slog.String("name", req.Name))
		return nil, status.Error(codes.Internal, services.ErrUpdateFailed)
	}

	slog.Debug("updated namespace", slog.String("name", req.Name))
	rsp.Namespace = namespace

	return rsp, nil
}

func (ns NamespacesService) DeleteNamespace(ctx context.Context, req *namespaces.DeleteNamespaceRequest) (*namespaces.DeleteNamespaceResponse, error) {
	slog.Debug("deleting namespace", slog.String("id", req.Id))
	rsp := &namespaces.DeleteNamespaceResponse{}

	if _, err := ns.dbClient.DeleteNamespace(ctx, req.Id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", err.Error()))
			return nil, status.Error(codes.NotFound, services.ErrNotFound)
		}
		slog.Error(services.ErrDeletionFailed, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletionFailed)
	}

	slog.Debug("deleted namespace", slog.String("id", req.Id))
	return rsp, nil
}
