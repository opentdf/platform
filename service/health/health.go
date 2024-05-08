package health

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

var (
	serviceHealthChecks = make(map[string]func(context.Context) error)
)

type HealthService struct { //nolint:revive // HealthService is a valid name for this struct
	healthpb.UnimplementedHealthServer
	logger *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "health",
		ServiceDesc: &healthpb.Health_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			err := srp.WellKnownConfig("health", map[string]any{
				"endpoint": "/healthz",
			})
			if err != nil {
				srp.Logger.Error("failed to set well-known config", slog.String("error", err.Error()))
			}
			return &HealthService{logger: srp.Logger}, func(_ context.Context, _ *runtime.ServeMux, _ any) error {
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

	switch req.GetService() {
	case "all":
		for service, check := range serviceHealthChecks {
			if err := check(ctx); err != nil {
				s.logger.ErrorContext(ctx, "service is not ready", slog.String("service", service), slog.String("error", err.Error()))
				return &healthpb.HealthCheckResponse{
					Status: healthpb.HealthCheckResponse_NOT_SERVING,
				}, nil
			}
		}
	default:
		if check, ok := serviceHealthChecks[req.GetService()]; ok {
			if err := check(ctx); err != nil {
				s.logger.ErrorContext(ctx, "service is not ready", slog.String("service", req.GetService()), slog.String("error", err.Error()))
				return &healthpb.HealthCheckResponse{
					Status: healthpb.HealthCheckResponse_NOT_SERVING,
				}, nil
			}
		} else {
			return &healthpb.HealthCheckResponse{
				Status: healthpb.HealthCheckResponse_SERVICE_UNKNOWN,
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

func RegisterReadinessCheck(namespace string, service func(context.Context) error) error {
	if _, ok := serviceHealthChecks[namespace]; ok {
		return status.Error(codes.AlreadyExists, "readiness check already registered")
	}
	serviceHealthChecks[namespace] = service

	return nil
}
