package services

import (
	"context"
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
	namespacesList := []*namespaces.Namespace{}

	rows, err := ns.dbClient.ListNamespaces(ctx)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrListingResource)
	}

	for rows.Next() {
		var namespace namespaces.Namespace
		if err := rows.Scan(&namespace.Id, &namespace.Name); err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, services.ErrListingResource)
		}
		namespacesList = append(namespacesList, &namespace)
	}

	return &namespaces.ListNamespacesResponse{
		Namespaces: namespacesList,
	}, nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *namespaces.GetNamespaceRequest) (*namespaces.GetNamespaceResponse, error) {
	slog.Debug("getting namespace", slog.String("id", req.Id))

	row, err := ns.dbClient.GetNamespace(ctx, req.Id)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	var namespace namespaces.Namespace
	if err := row.Scan(&namespace.Id, &namespace.Name); err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}

	slog.Debug("got namespace", slog.String("id", req.Id))
	return &namespaces.GetNamespaceResponse{
		Namespace: &namespace,
	}, nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *namespaces.CreateNamespaceRequest) (*namespaces.CreateNamespaceResponse, error) {
	slog.Debug("creating new namespace", slog.String("name", req.Namespace.Name))

	row, err := ns.dbClient.CreateNamespace(ctx, req.Namespace)
	if err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}

	var namespace namespaces.Namespace
	if err := row.Scan(&namespace.Id, &namespace.Name); err != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	}

	slog.Debug("created new namespace", slog.String("name", req.Namespace.Name))
	return &namespaces.CreateNamespaceResponse{
		Namespace: &namespace,
	}, nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *namespaces.UpdateNamespaceRequest) (*namespaces.UpdateNamespaceResponse, error) {
	slog.Debug("updating namespace", slog.String("name", req.Namespace.Name))

	row, err := ns.dbClient.UpdateNamespace(ctx, req.Namespace)
	if err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdatingResource)
	}

	var namespace namespaces.Namespace
	if err := row.Scan(&namespace.Id, &namespace.Name); err != nil {
		slog.Error(services.ErrUpdatingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrUpdatingResource)
	}

	slog.Debug("updated namespace", slog.String("name", req.Namespace.Name))
	return &namespaces.UpdateNamespaceResponse{
		Namespace: &namespace,
	}, nil
}

func (ns NamespacesService) DeleteNamespace(ctx context.Context, req *namespaces.DeleteNamespaceRequest) (*namespaces.DeleteNamespaceResponse, error) {
	slog.Debug("deleting namespace", slog.String("id", req.Id))

	if err := ns.dbClient.DeleteNamespace(ctx, req.Id); err != nil {
		slog.Error(services.ErrDeletingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrDeletingResource)
	}

	slog.Debug("deleted namespace", slog.String("id", req.Id))
	return &namespaces.DeleteNamespaceResponse{}, nil
}
