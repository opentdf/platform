package serviceregistry

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"connectrpc.com/connect"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/sdk"

	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/grpc"
)

type ServiceConfig map[string]any

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
type (
	HandlerServer       func(ctx context.Context, mux *runtime.ServeMux) error
	RegisterFunc[S any] func(RegistrationParams) (impl S, HandlerServer HandlerServer)
)

// DBRegister is a struct that holds the information needed to register a service with a database
type DBRegister struct {
	// Required is a flag that indicates whether the service requires a database connection.
	Required bool
	// Migrations is an embedded filesystem that contains the Goose SQL migrations for the service.
	// This is required to support the `migrate` command or the `runMigrations` configuration option.
	// More information on Goose can be found at https://github.com/pressly/goose
	Migrations *embed.FS
}

type IService interface {
	IsDBRequired() bool
	DBMigrations() *embed.FS
	GetNamespace() string
	GetServiceDesc() *grpc.ServiceDesc
	Start(ctx context.Context, params RegistrationParams) error
	IsStarted() bool
	Shutdown() error
	RegisterConnectRPCServiceHandler(context.Context, *server.ConnectRPC) error
	RegisterGRPCGatewayHandler(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error
	RegisterHTTPHandlers(context.Context, *runtime.ServeMux) error
}

// Service is a struct that holds the registration information for a service as well as the state
// of the service within the instance of the platform.
type Service[S any] struct {
	// Registration
	impl S
	// Started is a flag that indicates whether the service has been started
	Started bool
	// Close is a function that can be called to close the service
	Close func()
	// Service Options
	ServiceOptions[S]
}

type ServiceOptions[S any] struct {
	// Namespace is the namespace of the service. One or more gRPC services can be registered under
	// the same namespace.
	Namespace string
	// ServiceDesc is the gRPC service descriptor. For non-gRPC services, this can be mocked out,
	// but at minimum, the ServiceName field must be set
	ServiceDesc *grpc.ServiceDesc
	// RegisterFunc is the function that will be called to register the service
	RegisterFunc RegisterFunc[S]
	// HTTPHandlerFunc is the function that will be called to register extra http handlers
	httpHandlerFunc HandlerServer
	// ConnectRPCServiceHandler is the function that will be called to register the service with the
	ConnectRPCFunc func(S, ...connect.HandlerOption) (string, http.Handler)
	// Deprecated: Registers a gRPC service with the gRPC gateway
	GRPCGateayFunc func(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error)
	// DB is optional and used to register the service with a database
	DB DBRegister
}

func (s Service[S]) GetNamespace() string {
	return s.Namespace
}

func (s Service[S]) GetServiceDesc() *grpc.ServiceDesc {
	return s.ServiceDesc
}

func (s Service[S]) IsStarted() bool {
	return s.Started
}

func (s Service[S]) Shutdown() error {
	if s.Close != nil {
		s.Close()
	}
	return nil
}

func (s Service[S]) IsDBRequired() bool {
	return s.DB.Required
}

func (s Service[S]) DBMigrations() *embed.FS {
	return s.DB.Migrations
}

// Start starts the service and performs necessary initialization steps.
// It returns an error if the service is already started or if there is an issue running database migrations.
func (s *Service[S]) Start(ctx context.Context, params RegistrationParams) error {
	if s.Started {
		return fmt.Errorf("service already started")
	}

	if s.DB.Required && !params.DBClient.RanMigrations() && params.DBClient.MigrationsEnabled() {
		appliedMigrations, err := params.DBClient.RunMigrations(ctx, s.DB.Migrations)
		if err != nil {
			return fmt.Errorf("issue running database migrations: %w", err)
		}
		params.Logger.Info("database migrations complete",
			slog.Int("applied", appliedMigrations),
		)
	}

	s.impl, s.httpHandlerFunc = s.RegisterFunc(params)

	s.Started = true
	return nil
}

func (s Service[S]) RegisterConnectRPCServiceHandler(_ context.Context, connectRPC *server.ConnectRPC) error {
	if s.ConnectRPCFunc == nil {
		return fmt.Errorf("service did not register a handler")
	}
	connectRPC.ServiceReflection = append(connectRPC.ServiceReflection, s.GetServiceDesc().ServiceName)
	path, handler := s.ConnectRPCFunc(s.impl, connectRPC.Interceptors...)
	connectRPC.Mux.Handle(path, handler)
	return nil
}

// Deprecated: RegisterHTTPServer is deprecated and should not be used going forward.
// We will be looking onto other alternatives like bufconnect to replace this.
// RegisterHTTPServer registers an HTTP server with the service.
// It takes a context, a ServeMux, and an implementation function as parameters.
// If the service did not register a handler, it returns an error.
func (s *Service[S]) RegisterHTTPHandlers(ctx context.Context, mux *runtime.ServeMux) error {
	if s.httpHandlerFunc == nil {
		return fmt.Errorf("service did not register any handlers")
	}
	return s.httpHandlerFunc(ctx, mux)
}

// Deprecated: RegisterConnectRPCServiceHandler is deprecated and should not be used going forward.
// We will be looking onto other alternatives like bufconnect to replace this.
// RegisterConnectRPCServiceHandler registers an HTTP server with the service.
// It takes a context, a ServeMux, and an implementation function as parameters.
// If the service did not register a handler, it returns an error.
func (s Service[S]) RegisterGRPCGatewayHandler(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	if s.GRPCGateayFunc == nil {
		return fmt.Errorf("service did not register a handler")
	}
	return s.GRPCGateayFunc(ctx, mux, endpoint, opts)
}

// namespace represents a namespace in the service registry.
type Namespace struct {
	Mode     string
	Services []IService
}

// Registry represents a map of service namespaces.
type Registry map[string]Namespace

// NewServiceRegistry creates a new instance of the service registry.
func NewServiceRegistry() Registry {
	return make(Registry)
}

// RegisterCoreService registers a core service with the given registration information.
// It calls the RegisterService method of the Registry instance with the provided registration and service type "core".
// Returns an error if the registration fails.
func (reg Registry) RegisterCoreService(svc IService) error {
	return reg.RegisterService(svc, "core")
}

// RegisterService registers a service in the service registry.
// It takes a Registration object and a mode string as parameters.
// The Registration object contains information about the service to be registered,
// such as the namespace and service description.
// The mode string specifies the mode in which the service should be registered.
// It returns an error if the service is already registered in the specified namespace.
func (reg Registry) RegisterService(svc IService, mode string) error {
	// Can't directly modify structs within a map, so we need to copy the namespace
	copyNamespace := reg[svc.GetNamespace()]
	copyNamespace.Mode = mode
	if copyNamespace.Services == nil {
		copyNamespace.Services = make([]IService, 0)
	}
	found := slices.ContainsFunc(reg[svc.GetNamespace()].Services, func(s IService) bool {
		return s.GetServiceDesc().ServiceName == svc.GetServiceDesc().ServiceName
	})

	if found {
		return fmt.Errorf("service already registered namespace:%s service:%s", svc.GetNamespace(), svc.GetServiceDesc().ServiceName)
	}

	slog.Info("registered service", slog.String("namespace", svc.GetNamespace()), slog.String("service", svc.GetServiceDesc().ServiceName))
	copyNamespace.Services = append(copyNamespace.Services, svc)

	reg[svc.GetNamespace()] = copyNamespace
	return nil
}

// Shutdown stops all the services in the service registry.
// It iterates over each namespace and service in the registry,
// checks if the service has a Close method and if it has been started,
// and then calls the Close method to stop the service.
func (reg Registry) Shutdown() {
	for name, ns := range reg {
		for _, svc := range ns.Services {
			if svc.IsStarted() {
				slog.Info("stopping service", slog.String("namespace", name), slog.String("service", svc.GetServiceDesc().ServiceName))
				if err := svc.Shutdown(); err != nil {
					slog.Error("error stopping service", slog.String("namespace", name), slog.String("service", svc.GetServiceDesc().ServiceName), slog.String("error", err.Error()))
				}
			}
		}
	}
}

// GetNamespace returns the namespace with the given name from the service registry.
func (reg Registry) GetNamespace(namespace string) (Namespace, error) {
	ns, ok := reg[namespace]
	if !ok {
		return Namespace{}, fmt.Errorf("namespace not found: %s", namespace)
	}
	return ns, nil
}
