package acre

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	acrev1 "github.com/opentdf/opentdf-v2-poc/gen/acre/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
)

type acreServer struct {
	acrev1.UnimplementedResourcEncodingServiceServer
	dbClient *db.Client
}

func NewAcreServer(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	as := &acreServer{
		dbClient: dbClient,
	}
	acrev1.RegisterResourcEncodingServiceServer(grpcServer, as)
	err := acrev1.RegisterResourcEncodingServiceHandlerServer(context.Background(), mux, as)
	return err
}

func (s *acreServer) CreateResourceEncoding(ctx context.Context, req *acrev1.CreateResourceEncodingRequest) (*acrev1.CreateResourceEncodingResponse, error) {
	return nil, nil
}

func (s *acreServer) GetResourceEncoding(ctx context.Context, req *acrev1.GetResourceEncodingRequest) (*acrev1.GetResourceEncodingResponse, error) {
	return nil, nil
}

func (s *acreServer) UpdateResourceEncoding(ctx context.Context, req *acrev1.UpdateResourceEncodingRequest) (*acrev1.UpdateResourceEncodingResponse, error) {
	return nil, nil
}

func (s *acreServer) DeleteResourceEncoding(ctx context.Context, req *acrev1.DeleteResourceEncodingRequest) (*acrev1.DeleteResourceEncodingResponse, error) {
	return nil, nil
}
