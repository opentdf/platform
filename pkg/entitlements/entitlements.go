package entitlements

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	entitlmentsv1 "github.com/opentdf/opentdf-v2-poc/gen/entitlements/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
)

type entitlementsServer struct {
	entitlmentsv1.UnimplementedEntitlementsServiceServer
	dbClient *db.Client
	grpcConn *grpc.ClientConn
}

func NewEntitlementsServer(dbClient *db.Client, g *grpc.Server, grpcInprocess *grpc.Server, clientConn *grpc.ClientConn, s *runtime.ServeMux) error {
	as := &entitlementsServer{
		dbClient: dbClient,
		grpcConn: clientConn,
	}
	entitlmentsv1.RegisterEntitlementsServiceServer(g, as)
	if grpcInprocess != nil {
		entitlmentsv1.RegisterEntitlementsServiceServer(grpcInprocess, as)
	}
	err := entitlmentsv1.RegisterEntitlementsServiceHandlerServer(context.Background(), s, as)
	return err
}

func (s entitlementsServer) GetEntitlements(ctx context.Context, req *entitlmentsv1.GetEntitlementsRequest) (*entitlmentsv1.GetEntitlementsResponse, error) {
	acseClient := acsev1.NewSubjectEncodingServiceClient(s.grpcConn)
	mappings, err := acseClient.ListSubjectMappings(ctx, &acsev1.ListSubjectMappingsRequest{})
	if err != nil {
		return &entitlmentsv1.GetEntitlementsResponse{}, err
	}
	for _, mapping := range mappings.SubjectMappings {
		slog.Info("mapping", slog.String("name", mapping.SubjectAttribute))
	}
	return &entitlmentsv1.GetEntitlementsResponse{}, nil
}
