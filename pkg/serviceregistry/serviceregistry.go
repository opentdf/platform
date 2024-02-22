package serviceregistry

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/config"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	"google.golang.org/grpc"
)

type RegistrationParams struct {
	Config   config.Config
	OTDF     *server.OpenTDFServer
	DBClient *db.Client
	Engine   *opa.Engine
}
type HandlerServer func(ctx context.Context, mux *runtime.ServeMux, server any) error
type RegisterFunc func(RegistrationParams) (Impl any, HandlerServer HandlerServer)
type Registration struct {
	Namespace    string
	ServiceDesc  *grpc.ServiceDesc
	RegisterFunc RegisterFunc
}

type Service struct {
	Registration
	Config  config.ServiceConfig
	Enabled bool
}

// Map of namespaces to services
var RegisteredServices map[string]map[string]Service

func RegisterService(r Registration) {
	if RegisteredServices == nil {
		RegisteredServices = make(map[string]map[string]Service, 0)
	}
	if RegisteredServices[r.Namespace] == nil {
		RegisteredServices[r.Namespace] = make(map[string]Service, 0)
	}

	if RegisteredServices[r.Namespace][r.ServiceDesc.ServiceName].RegisterFunc != nil {
		slog.Warn("service already registered", slog.String("namespace", r.Namespace), slog.String("service", r.ServiceDesc.ServiceName))
		return
	}

	slog.Info("registered service", slog.String("namespace", r.Namespace), slog.String("service", r.ServiceDesc.ServiceName))
	RegisteredServices[r.Namespace][r.ServiceDesc.ServiceName] = Service{
		Registration: r,
	}
}
