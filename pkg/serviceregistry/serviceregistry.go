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

type ServiceRegisterArgs struct {
	Config   config.Config
	OTDF     *server.OpenTDFServer
	DBClient *db.Client
	Engine   *opa.Engine
}

type ServiceHandlerServer func(ctx context.Context, mux *runtime.ServeMux, server any) error

type ServiceRegisterFunc func(ServiceRegisterArgs) (Impl any, HandlerServer ServiceHandlerServer)

type Service struct {
	Namespace string
	Desc      *grpc.ServiceDesc
	Func      ServiceRegisterFunc
	Config    config.ServiceConfig
	Enabled   bool
}

// Map of namespaces to services
var RegisteredServices map[string]map[string]Service

func RegisterService(ns string, desc *grpc.ServiceDesc, fn ServiceRegisterFunc) {
	if RegisteredServices[ns] == nil {
		RegisteredServices[ns] = make(map[string]Service)
	}

	if RegisteredServices[ns][desc.ServiceName].Func != nil {
		slog.Warn("service already registered", slog.String("namespace", ns), slog.String("service", desc.ServiceName))
		return
	}

	slog.Info("registered service", slog.String("namespace", ns), slog.String("service", desc.ServiceName))
	RegisteredServices[ns][desc.ServiceName] = Service{
		Namespace: ns,
		Desc:      desc,
		Func:      fn,
	}
}
