package serviceregistry

import (
	"context"
	"embed"
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
	ExtraProps map[string]interface{} `json:"-" mapstructure:",remain"`
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

type DBRegister struct {
	Required bool
	// Required to support automatic migrations
	Migrations *embed.FS
}

type Registration struct {
	Namespace    string
	ServiceDesc  *grpc.ServiceDesc
	RegisterFunc RegisterFunc

	// Optional to specify if the service requires a database connection
	DB DBRegister
}

type Service struct {
	Registration
	Started bool
	Close   func()
}

type ServiceMap map[string]Service
type NamespaceMap map[string]ServiceMap

// Map of namespaces to services
var RegisteredServices NamespaceMap

func RegisterService(r Registration) error {
	if RegisteredServices == nil {
		RegisteredServices = make(NamespaceMap, 0)
	}
	if RegisteredServices[r.Namespace] == nil {
		RegisteredServices[r.Namespace] = make(ServiceMap, 0)
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
