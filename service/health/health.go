package health

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type HealthService struct { //nolint:revive // HealthService is a valid name for this struct
	healthpb.UnimplementedHealthServer
	db *db.Client
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "health",
		ServiceDesc: &healthpb.Health_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			err := srp.WellKnownConfig("health", map[string]any{
				"endpoints": map[string]any{
					"liveness":  "/healthz?service=liveness",
					"readiness": "/healthz?service=readiness",
				},
			})
			if err != nil {
				panic(err)
			}
			return &HealthService{db: srp.DBClient}, func(_ context.Context, _ *runtime.ServeMux, _ any) error {
				return nil
			}
		},
	}
}

func (s HealthService) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if req.GetService() == "" {
		return &healthpb.HealthCheckResponse{
			Status: healthpb.HealthCheckResponse_SERVING,
		}, nil
	}

	// Check to see if we are doing a readiness probe
	if req.GetService() == "readiness" {
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

func (s HealthService) Watch(_ *healthpb.HealthCheckRequest, _ healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "unimplemented")
}
