package serviceregistry

import (
	"context"
	"embed"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/sdk"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/grpc"
)

// ServiceConfig is a struct that holds the configuration for a service and used for the global
// config rollup powered by Viper (https://github.com/spf13/viper)
type ServiceConfig struct {
	Enabled    bool                   `yaml:"enabled"`
	Remote     RemoteServiceConfig    `yaml:"remote"`
	ExtraProps map[string]interface{} `json:"-" mapstructure:",remain"`
}

type RemoteServiceConfig struct {
	Endpoint string `yaml:"endpoint"`
}

// RegistrationParams is a struct that holds the parameters needed to register a service
// with the service registry. These parameters are passed to the RegisterFunc function defined
// in the Registration struct.
type RegistrationParams struct {
	// Config scoped to the service config. Since the main config contains all the service configs,
	// which could have need-to-know information we don't want to expose it to all services.
	Config ServiceConfig
	// OTDF is the OpenTDF server that can be used to interact with the OpenTDFServer instance.
	OTDF *server.OpenTDFServer
	// DBClient is the database client that can be used to interact with the database. This client
	// is scoped to the service namespace and will not be shared with other service namespaces.
	DBClient *db.Client
	// Engine is the OPA engine that can be used to interact with the OPA server. Generally, the
	// only service that needs to interact with OPA is the authorization service.
	Engine *opa.Engine
	// SDK is the OpenTDF SDK that can be used to interact with the OpenTDF SDK. This is useful for
	// gRPC Inter Process Communication (IPC) between services. This ensures the services are
	// communicating with each other by contract as well as supporting the various deployment models
	// that OpenTDF supports.
	SDK *sdk.SDK
	// Logger is the logger that can be used to log messages. This logger is scoped to the service
	Logger *logger.Logger

	////// The following functions are optional and intended to be called by the service //////

	// RegisterWellKnownConfig is a function that can be used to register a well-known configuration
	WellKnownConfig func(namespace string, config any) error
	// RegisterReadinessCheck is a function that can be used to register a readiness check for the
	// service. This is useful for services that need to perform some initialization before they are
	// ready to serve requests. This function should be called in the RegisterFunc function.
	RegisterReadinessCheck func(namespace string, check func(context.Context) error) error
}
type HandlerServer func(ctx context.Context, mux *runtime.ServeMux, server any) error
type RegisterFunc func(RegistrationParams) (Impl any, HandlerServer HandlerServer)

// Registration is a struct that holds the information needed to register a service
type Registration struct {
	// Namespace is the namespace of the service. One or more gRPC services can be registered under
	// the same namespace.
	Namespace string
	// ServiceDesc is the gRPC service descriptor. For non-gRPC services, this can be mocked out,
	// but at minimum, the ServiceName field must be set
	ServiceDesc *grpc.ServiceDesc
	// RegisterFunc is the function that will be called to register the service
	RegisterFunc RegisterFunc

	// DB is optional and used to register the service with a database
	DB DBRegister
}

// DBRegister is a struct that holds the information needed to register a service with a database
type DBRegister struct {
	// Required is a flag that indicates whether the service requires a database connection.
	Required bool
	// Migrations is an embedded filesystem that contains the Goose SQL migrations for the service.
	// This is required to support the `migrate` command or the `runMigrations` configuration option.
	// More information on Goose can be found at https://github.com/pressly/goose
	Migrations *embed.FS
}

// Service is a struct that holds the registration information for a service as well as the state
// of the service within the instance of the platform.
type Service struct {
	Registration
	// Started is a flag that indicates whether the service has been started
	Started bool
	// Close is a function that can be called to close the service
	Close func()
}

type ServiceMap map[string]Service
type NamespaceMap map[string]ServiceMap

// RegisteredServices is a map of namespaces to services
// TODO remove the global variable and move towards a more functional approach
var RegisteredServices NamespaceMap

// RegisterService is a function that registers a service with the service registry.
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
