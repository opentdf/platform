package serviceregistry

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/sdk"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"

	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/trust"
)

// RegistrationParams is a struct that holds the parameters needed to register a service
// with the service registry. These parameters are passed to the RegisterFunc function defined
// in the Registration struct.
type RegistrationParams struct {
	// Config scoped to the service config. Since the main config contains all the service configs,
	// which could have need-to-know information we don't want to expose it to all services.
	Config config.ServiceConfig
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
	trace.Tracer

	// NewCacheClient is a function that can be used to create a new cache instance for the service
	NewCacheClient func(cache.Options) (*cache.Cache, error)

	// KeyManagerFactories are the registered key manager factories that can be used to create
	// key managers for the service to use.
	// Prefer KeyManagerCtxFactories
	// EXPERIMENTAL
	KeyManagerFactories []trust.NamedKeyManagerFactory

	// KeyManagerCtxFactories are the registered key manager context factories that can be used to create
	// key managers for the service to use.
	// EXPERIMENTAL
	KeyManagerCtxFactories []trust.NamedKeyManagerCtxFactory

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
	// Allow services to implement handling for config changes as direced by caller
	OnConfigUpdateHook func(context.Context, config.ServiceConfig) error
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
	GetVersion() string
	GetServiceDesc() *grpc.ServiceDesc
	Start(ctx context.Context, params RegistrationParams) error
	IsStarted() bool
	Shutdown() error
	RegisterConfigUpdateHook(ctx context.Context, hookAppender func(config.ChangeHook)) error
	RegisterConnectRPCServiceHandler(context.Context, *server.ConnectRPC) error
	RegisterGRPCGatewayHandler(context.Context, *runtime.ServeMux, *grpc.ClientConn) error
	RegisterHTTPHandlers(context.Context, *runtime.ServeMux) error
}

// Service is a struct that holds the registration information for a service as well as the state
// of the service within the instance of the platform.
type Service[S any] struct {
	// IService (registration)
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
	// Version is the major version of the service according to the protocol buffer definition.
	Version string
	// ServiceDesc is the gRPC service descriptor. For non-gRPC services, this can be mocked out,
	// but at minimum, the ServiceName field must be set
	ServiceDesc *grpc.ServiceDesc
	// OnConfigUpdate is a hook to handle in-service actions when config changes
	OnConfigUpdate OnConfigUpdateHook
	// RegisterFunc is the function that will be called to register the service
	RegisterFunc RegisterFunc[S]
	// HTTPHandlerFunc is the function that will be called to register extra http handlers
	httpHandlerFunc HandlerServer
	// ConnectRPCServiceHandler is the function that will be called to register the service with the
	ConnectRPCFunc func(S, ...connect.HandlerOption) (string, http.Handler)
	// Deprecated: Registers a gRPC service with the gRPC gateway
	GRPCGatewayFunc func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error
	// DB is optional and used to register the service with a database
	DB DBRegister
}

func (s Service[S]) GetNamespace() string {
	return s.Namespace
}

func (s Service[S]) GetVersion() string {
	return s.Version
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
		return errors.New("service already started")
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

// RegisterConfigUpdateHook appends a registered service's onConfigUpdateHook to any watching config loaders.
func (s Service[S]) RegisterConfigUpdateHook(ctx context.Context, hookAppender func(config.ChangeHook)) error {
	// If no hook is registered, exit
	if s.OnConfigUpdate != nil {
		var onChange config.ChangeHook = func(cfg config.ServicesMap) error {
			slog.Debug("service config change hook called",
				slog.String("namespace", s.GetNamespace()),
				slog.String("service", s.GetServiceDesc().ServiceName),
			)
			return s.OnConfigUpdate(ctx, cfg[s.GetNamespace()])
		}
		hookAppender(onChange)
	}
	return nil
}

func (s Service[S]) RegisterConnectRPCServiceHandler(_ context.Context, connectRPC *server.ConnectRPC) error {
	if s.ConnectRPCFunc == nil {
		return errors.New("service did not register a handler")
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
		return errors.New("service did not register any handlers")
	}
	return s.httpHandlerFunc(ctx, mux)
}

// Deprecated: RegisterConnectRPCServiceHandler is deprecated and should not be used going forward.
// We will be looking onto other alternatives like bufconnect to replace this.
// RegisterConnectRPCServiceHandler registers an HTTP server with the service.
// It takes a context, a ServeMux, and an implementation function as parameters.
// If the service did not register a handler, it returns an error.
func (s Service[S]) RegisterGRPCGatewayHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	if s.GRPCGatewayFunc == nil {
		return errors.New("service did not register a handler")
	}
	return s.GRPCGatewayFunc(ctx, mux, conn)
}

// namespace represents a namespace in the service registry.
type Namespace struct {
	Mode     string
	Version  string
	Services []IService
}

// IsEnabled checks if this namespace should be enabled based on configured modes.
// Returns true if any of the configured modes match this namespace's mode,
// or if "all" mode is configured, or if this namespace is "essential".
func (n Namespace) IsEnabled(configuredModes []string) bool {
	for _, configMode := range configuredModes {
		// Case-insensitive comparison for mode matching
		if strings.EqualFold(configMode, string(ModeALL)) ||
			strings.EqualFold(n.Mode, string(ModeEssential)) ||
			strings.EqualFold(configMode, n.Mode) {
			return true
		}
	}
	return false
}

type ServiceName interface {
	String() string
}

// ServiceConfiguration represents a service with its associated modes and implementations.
type ServiceConfiguration struct {
	Name     ServiceName
	Modes    []ModeName
	Services []IService
}

// Registry represents a service registry with namespaces and their registration order.
type Registry struct {
	mu         sync.RWMutex
	namespaces map[string]*Namespace
	order      []string
}

// NewServiceRegistry creates a new instance of the service registry.
func NewServiceRegistry() *Registry {
	return &Registry{
		namespaces: make(map[string]*Namespace),
		order:      make([]string, 0),
	}
}

type NamespaceInfo struct {
	Name      string
	Namespace *Namespace
}

// GetNamespaces returns all namespaces in the registry
func (reg *Registry) GetNamespaces() []NamespaceInfo {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	namespaceInfo := make([]NamespaceInfo, len(reg.order))
	for i, name := range reg.order {
		namespaceInfo[i] = NamespaceInfo{Name: name, Namespace: reg.namespaces[name]}
	}
	return namespaceInfo
}

// RegisterService registers a service in the service registry.
// It takes an serviceregistry.IService and a mode string as parameters.
// The IService implementation contains information about the service to be registered,
// such as the namespace and service description.
// The mode string specifies the mode in which the service should be registered.
// It returns an error if the service is already registered in the specified namespace.
func (reg *Registry) RegisterService(svc IService, mode ModeName) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	nsName := svc.GetNamespace()

	// Get or create the namespace
	ns, exists := reg.namespaces[nsName]
	if !exists {
		ns = &Namespace{
			Mode:     mode.String(),
			Services: make([]IService, 0),
		}
		reg.namespaces[nsName] = ns
		reg.order = append(reg.order, nsName)
	}

	// Check if a service with the same name is already registered in this namespace.
	found := slices.ContainsFunc(ns.Services, func(s IService) bool {
		return s.GetServiceDesc().ServiceName == svc.GetServiceDesc().ServiceName
	})
	if found {
		return fmt.Errorf("service already registered namespace:%s service:%s", nsName, svc.GetServiceDesc().ServiceName)
	}

	slog.Info(
		"registered service",
		slog.String("namespace", nsName),
		slog.String("service", svc.GetServiceDesc().ServiceName),
	)

	ns.Mode = mode.String()
	ns.Services = append(ns.Services, svc)

	return nil
}

// Shutdown stops all the registered services in the reverse order of registration.
// If a service is started and has a Close method, the Close method will be called.
func (reg *Registry) Shutdown() {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	for nsIdx := len(reg.order) - 1; nsIdx >= 0; nsIdx-- {
		name := reg.order[nsIdx]
		ns := reg.namespaces[name]
		for serviceIdx := len(ns.Services) - 1; serviceIdx >= 0; serviceIdx-- {
			svc := ns.Services[serviceIdx]
			if svc.IsStarted() {
				slog.Info("stopping service",
					slog.String("namespace", name),
					slog.String("service", svc.GetServiceDesc().ServiceName),
				)
				if err := svc.Shutdown(); err != nil {
					slog.Error("error stopping service",
						slog.String("namespace", name),
						slog.String("service", svc.GetServiceDesc().ServiceName),
						slog.Any("error", err),
					)
				}
			}
		}
	}
}

// GetNamespace returns the namespace with the given name from the service registry.
func (reg *Registry) GetNamespace(namespace string) (*Namespace, error) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	ns, ok := reg.namespaces[namespace]
	if !ok {
		return nil, &ServiceConfigError{
			Type:    "lookup",
			Message: "namespace not found: " + namespace,
		}
	}
	return ns, nil
}

// RegisterServicesFromConfiguration handles service registration using declarative configuration with negation support.
func (reg *Registry) RegisterServicesFromConfiguration(modes []string, configurations []ServiceConfiguration) ([]string, error) {
	// Parse modes to separate inclusions and exclusions
	includedModes, excludedServices, err := ParseModesWithNegation(modes)
	if err != nil {
		return nil, err
	}

	registeredServices := make([]string, 0)

	// Loop through each service configuration
	for _, config := range configurations {
		// Check if this service is explicitly excluded
		if slices.Contains(excludedServices, config.Name.String()) {
			slog.Debug("skipping excluded service", slog.String("service", config.Name.String()))
			continue
		}

		var nsMode ModeName
		for _, requestedMode := range includedModes {
			if slices.Contains(config.Modes, requestedMode) {
				nsMode = requestedMode
				break
			}
		}

		if nsMode == "" {
			continue
		}

		registeredServices = append(registeredServices, config.Name.String())

		// Register all services using their own defined namespace
		for _, service := range config.Services {
			// Register the service with the determined mode
			if err := reg.RegisterService(service, nsMode); err != nil {
				return nil, err
			}
		}
	}

	return registeredServices, nil
}
