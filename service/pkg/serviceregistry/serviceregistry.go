package serviceregistry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/sdk"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/db"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	"google.golang.org/grpc"
)

type ServiceConfig struct {
	Enabled    bool                   `yaml:"enabled"`
	Remote     RemoteServiceConfig    `yaml:"remote"`
	ExtraProps map[string]interface{} `json:"-"`
}

type RemoteServiceConfig struct {
	Endpoint string `yaml:"endpoint"`
}

type RegistrationParams struct {
	Config          ServiceConfig
	OTDF            *server.OpenTDFServer
	DBClient        *db.Client
	Engine          *opa.Engine
	SDK             *sdk.SDK
	WellKnownConfig func(namespace string, config any) error
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
}

// Map of namespaces to services
var RegisteredServices map[string]map[string]Service

func RegisterService(r Registration) error {
	if RegisteredServices == nil {
		RegisteredServices = make(map[string]map[string]Service, 0)
	}
	if RegisteredServices[r.Namespace] == nil {
		RegisteredServices[r.Namespace] = make(map[string]Service, 0)
	}

	if RegisteredServices[r.Namespace][r.ServiceDesc.ServiceName].RegisterFunc != nil {
		return fmt.Errorf("service already registered namespace:%s service:%s", r.Namespace, r.ServiceDesc.ServiceName)
	}

	slog.Info("registered service", slog.String("namespace", r.Namespace), slog.String("service", r.ServiceDesc.ServiceName))
	RegisteredServices[r.Namespace][r.ServiceDesc.ServiceName] = Service{
		Registration: r,
	}
	return nil
}
