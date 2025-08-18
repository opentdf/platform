package health

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
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
				hs := HealthService{logger: srp.Logger}
				return hs, func(_ context.Context, mux *runtime.ServeMux) error {
					err := mux.HandlePath(http.MethodGet, "/healthz", func(w http.ResponseWriter, r *http.Request, _ map[string]string) { //nolint:contextcheck // check is not relevant here
						resp, err := hs.Check(context.Background(), &grpchealth.CheckRequest{
							Service: r.URL.Query().Get("service"),
						})
						if err != nil {
							http.Error(w, err.Error(), http.StatusInternalServerError)
							return
						}
						status := map[string]interface{}{"status": strings.ToUpper(resp.Status.String())}
						if resp.Status != grpchealth.StatusServing {
							w.WriteHeader(http.StatusServiceUnavailable)
							if err := json.NewEncoder(w).Encode(status); err != nil {
								srp.Logger.Error("failed to encode health status", slog.String("error", err.Error()))
							}

							return
						}
						w.WriteHeader(http.StatusOK)
						if err := json.NewEncoder(w).Encode(status); err != nil {
							srp.Logger.Error("failed to encode health status", slog.String("error", err.Error()))
						}
					})
					if err != nil {
						panic(errors.Join(errors.New("failed to register healthz endpoint"), err))
					}

					return nil
				}
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
				s.logger.ErrorContext(ctx,
					"service is not ready",
					slog.String("service", service),
					slog.Any("error", err),
				)
				return &grpchealth.CheckResponse{
					Status: grpchealth.StatusNotServing,
				}, nil
			}
		}
	default:
		if check, ok := serviceHealthChecks[req.Service]; ok {
			if err := check(ctx); err != nil {
				s.logger.ErrorContext(ctx,
					"service is not ready",
					slog.String("service", req.Service),
					slog.Any("error", err),
				)
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
