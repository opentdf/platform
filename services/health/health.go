package health

import (
	"context"
	"log/slog"

	"github.com/opentdf/platform/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type HealthService struct {
	healthpb.UnimplementedHealthServer
	db *db.Client
}

func NewHealthService(dbClient *db.Client, gs []*grpc.Server) {
	hs := &HealthService{
		db: dbClient,
	}
	for _, g := range gs {
		healthpb.RegisterHealthServer(g, hs)
	}
}

func (s HealthService) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if req.Service == "" {
		return &healthpb.HealthCheckResponse{
			Status: healthpb.HealthCheckResponse_SERVING,
		}, nil
	}

	// Check to see if we are doing a readiness probe
	if req.Service == "readiness" {
		// Check the database connection
		if err := s.db.Pgx.Ping(ctx); err != nil {
			slog.Error("database connection is not ready", slog.String("error", err.Error()))
			return &healthpb.HealthCheckResponse{
				Status: healthpb.HealthCheckResponse_NOT_SERVING,
			}, nil
		}
	}

	return &healthpb.HealthCheckResponse{
		Status: healthpb.HealthCheckResponse_SERVING,
	}, nil
}

func (s HealthService) Watch(req *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "unimplemented")
}
