package health

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var serviceHealthChecks = make(map[string]func(context.Context) error)

type HealthService struct { //nolint:revive // HealthService is a valid name for this struct
	logger *logger.Logger
}

func NewRegistration() *serviceregistry.Service[grpchealth.Checker] {
	return &serviceregistry.Service[grpchealth.Checker]{
		ServiceOptions: serviceregistry.ServiceOptions[grpchealth.Checker]{
			Namespace:      "health",
			ServiceDesc:    &healthpb.Health_ServiceDesc,
			ConnectRPCFunc: grpchealth.NewHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (grpchealth.Checker, serviceregistry.HandlerServer) {
				err := srp.WellKnownConfig("health", map[string]any{
					"endpoint": "/healthz",
				})
				if err != nil {
					srp.Logger.Error("failed to set well-known config", slog.String("error", err.Error()))
				}
				return HealthService{logger: srp.Logger}, nil
			},
		},
	}
}

func (s HealthService) Check(ctx context.Context, req *grpchealth.CheckRequest) (*grpchealth.CheckResponse, error) {
	if req.Service == "" {
		return &grpchealth.CheckResponse{
			Status: grpchealth.StatusServing,
		}, nil
	}

	switch req.Service {
	case "all":
		for service, check := range serviceHealthChecks {
			if err := check(ctx); err != nil {
				s.logger.ErrorContext(ctx, "service is not ready", slog.String("service", service), slog.String("error", err.Error()))
				return &grpchealth.CheckResponse{
					Status: grpchealth.StatusNotServing,
				}, nil
			}
		}
	default:
		if check, ok := serviceHealthChecks[req.Service]; ok {
			if err := check(ctx); err != nil {
				s.logger.ErrorContext(ctx, "service is not ready", slog.String("service", req.Service), slog.String("error", err.Error()))
				return &grpchealth.CheckResponse{
					Status: grpchealth.StatusNotServing,
				}, nil
			}
		} else {
			return &grpchealth.CheckResponse{
				Status: grpchealth.StatusUnknown,
			}, nil
		}
	}

	return &grpchealth.CheckResponse{
		Status: grpchealth.StatusServing,
	}, nil
}

func (s HealthService) Watch(_ *healthpb.HealthCheckRequest, _ healthpb.Health_WatchServer) error {
	return connect.NewError(connect.CodeUnimplemented, errors.New("unimplemented"))
}

func RegisterReadinessCheck(namespace string, service func(context.Context) error) error {
	if _, ok := serviceHealthChecks[namespace]; ok {
		return errors.New("readiness check already registered")
	}
	serviceHealthChecks[namespace] = service

	return nil
}
