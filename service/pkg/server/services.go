package server

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/authorization"
	authorizationV2 "github.com/opentdf/platform/service/authorization/v2"
	"github.com/opentdf/platform/service/entityresolution"
	entityresolutionV2 "github.com/opentdf/platform/service/entityresolution/v2"
	"github.com/opentdf/platform/service/health"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/kas"
	logging "github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy"
	"github.com/opentdf/platform/service/tracing"
	"github.com/opentdf/platform/service/trust"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const (
	modeALL       = "all"
	modeCore      = "core"
	modeKAS       = "kas"
	modeERS       = "entityresolution"
	modeEssential = "essential"

	serviceKAS              = "kas"
	servicePolicy           = "policy"
	serviceWellKnown        = "wellknown"
	serviceEntityResolution = "entityresolution"
	serviceAuthorization    = "authorization"
)

// registerEssentialServices registers the essential services to the given service registry.
// It takes a serviceregistry.Registry as input and returns an error if registration fails.
func registerEssentialServices(reg *serviceregistry.Registry) error {
	essentialServices := []serviceregistry.IService{
		health.NewRegistration(),
	}
	// Register the essential services
	for _, s := range essentialServices {
		if err := reg.RegisterService(s, modeEssential); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}

// registerCoreServices registers the core services based on the provided mode.
// It returns the list of registered services and any error encountered during registration.
func registerCoreServices(reg *serviceregistry.Registry, mode []string) ([]string, error) {
	var (
		services           []serviceregistry.IService
		registeredServices []string
	)

	for _, m := range mode {
		switch m {
		case "all":
			registeredServices = append(registeredServices, []string{servicePolicy, serviceAuthorization, serviceKAS, serviceWellKnown, serviceEntityResolution}...)
			services = append(services, []serviceregistry.IService{
				authorization.NewRegistration(),
				authorizationV2.NewRegistration(),
				kas.NewRegistration(),
				wellknown.NewRegistration(),
				entityresolution.NewRegistration(),
				entityresolutionV2.NewRegistration(),
			}...)
			services = append(services, policy.NewRegistrations()...)
		case "core":
			registeredServices = append(registeredServices, []string{servicePolicy, serviceAuthorization, serviceWellKnown}...)
			services = append(services, []serviceregistry.IService{
				authorization.NewRegistration(),
				authorizationV2.NewRegistration(),
				wellknown.NewRegistration(),
			}...)
			services = append(services, policy.NewRegistrations()...)
		case "kas":
			// If the mode is "kas", register only the KAS service
			registeredServices = append(registeredServices, serviceKAS)
			if err := reg.RegisterService(kas.NewRegistration(), modeKAS); err != nil {
				return nil, err //nolint:wrapcheck // We are all friends here
			}
		case "entityresolution":
			// If the mode is "entityresolution", register only the ERS service (v1 and v2)
			registeredServices = append(registeredServices, serviceEntityResolution)
			if err := reg.RegisterService(entityresolution.NewRegistration(), modeERS); err != nil {
				return nil, err //nolint:wrapcheck // We are all friends here
			}
			if err := reg.RegisterService(entityresolutionV2.NewRegistration(), modeERS); err != nil {
				return nil, err //nolint:wrapcheck // We are all friends here
			}
		default:
			continue
		}
	}

	// Register the services
	for _, s := range services {
		if err := reg.RegisterCoreService(s); err != nil {
			return nil, err //nolint:wrapcheck // We are all friends here
		}
	}

	return registeredServices, nil
}

type startServicesParams struct {
	cfg                    *config.Config
	otdf                   *server.OpenTDFServer
	client                 *sdk.SDK
	logger                 *logging.Logger
	reg                    *serviceregistry.Registry
	cacheManager           *cache.Manager
	keyManagerCtxFactories []trust.NamedKeyManagerCtxFactory
}

// startServices iterates through the registered namespaces and starts the services
// based on the configuration and namespace mode. It creates a new service logger
// and a database client if required. It registers the services with the gRPC server,
// in-process gRPC server, and gRPC gateway. Finally, it logs the status of each service.
func startServices(ctx context.Context, params startServicesParams) (func(), error) {
	var gatewayCleanup func()

	cfg := params.cfg
	otdf := params.otdf
	client := params.client
	logger := params.logger
	reg := params.reg
	cacheManager := params.cacheManager
	keyManagerCtxFactories := params.keyManagerCtxFactories

	// Create a copy of the key manager factories as the context version for legacy services that don't load the new version with context
	var keyManagerFactories []trust.NamedKeyManagerFactory
	for _, factory := range keyManagerCtxFactories {
		keyManagerFactories = append(keyManagerFactories, trust.NamedKeyManagerFactory{
			Name: factory.Name,
			//nolint:contextcheck // This is called later, so will be in a new context
			Factory: func(opts *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
				return factory.Factory(context.Background(), opts)
			},
		})
	}

	for _, ns := range reg.GetNamespaces() {
		namespace, err := reg.GetNamespace(ns)
		if err != nil {
			// This is an internal inconsistency and should not happen.
			return nil, fmt.Errorf("namespace not found: %w", err)
		}
		// modeEnabled checks if the mode is enabled based on the configuration and namespace mode.
		// It returns true if the mode is "all" or "essential" in the configuration, or if it matches the namespace mode.
		modeEnabled := slices.ContainsFunc(cfg.Mode, func(m string) bool {
			if strings.EqualFold(m, modeALL) || strings.EqualFold(namespace.Mode, modeEssential) {
				return true
			}
			return strings.EqualFold(m, namespace.Mode)
		})

		// Skip the namespace if the mode is not enabled
		if !modeEnabled {
			logger.Info("skipping namespace",
				slog.String("namespace", ns),
				slog.String("mode", namespace.Mode),
			)
			continue
		}

		svcLogger := logger.With("namespace", ns)
		extractedLogLevel, err := extractServiceLoggerConfig(cfg.Services[ns])

		// If ns has log_level in config, create new logger with that level
		if err == nil {
			if extractedLogLevel != cfg.Logger.Level {
				slog.Debug("configuring logger")
				var newLoggerConfig logging.Config = cfg.Logger
				newLoggerConfig.Level = extractedLogLevel
				newSvcLogger, err := logging.NewLogger(newLoggerConfig)
				// only assign if logger successfully created
				if err == nil {
					svcLogger = newSvcLogger.With("namespace", ns)
				}
			}
		}

		var svcDBClient *db.Client
		tracer := otel.Tracer(tracing.ServiceName)

		for _, svc := range namespace.Services {
			// Get new db client if it is required and not already created
			if svc.IsDBRequired() && svcDBClient == nil {
				logger.Debug("creating database client", slog.String("namespace", ns))
				var err error
				svcDBClient, err = newServiceDBClient(ctx, cfg.Logger, cfg.DB, tracer, ns, svc.DBMigrations())
				if err != nil {
					return func() {}, err
				}
			}
			if svc.GetVersion() != "" {
				svcLogger = svcLogger.With("version", svc.GetVersion())
			}

			// Function to create a cache given cache options
			var createCacheClient func(cache.Options) (*cache.Cache, error) = func(options cache.Options) (*cache.Cache, error) {
				slog.Info("creating cache client for",
					slog.String("namespace", ns),
					slog.String("service", svc.GetServiceDesc().ServiceName),
				)
				cacheClient, err := cacheManager.NewCache(ns, svcLogger, options)
				if err != nil {
					return nil, fmt.Errorf("issue creating cache client for %s: %w", ns, err)
				}
				return cacheClient, nil
			}

			err = svc.Start(ctx, serviceregistry.RegistrationParams{
				Config:                 cfg.Services[svc.GetNamespace()],
				Logger:                 svcLogger,
				DBClient:               svcDBClient,
				SDK:                    client,
				WellKnownConfig:        wellknown.RegisterConfiguration,
				RegisterReadinessCheck: health.RegisterReadinessCheck,
				OTDF:                   otdf, // TODO: REMOVE THIS
				Tracer:                 tracer,
				NewCacheClient:         createCacheClient,
				KeyManagerFactories:    keyManagerFactories,
				KeyManagerCtxFactories: keyManagerCtxFactories,
			})
			if err != nil {
				return func() {}, err
			}

			if err := svc.RegisterConfigUpdateHook(ctx, cfg.AddOnConfigChangeHook); err != nil {
				return func() {}, fmt.Errorf("failed to register config update hook: %w", err)
			}

			// Register Connect RPC Services
			if err := svc.RegisterConnectRPCServiceHandler(ctx, otdf.ConnectRPC); err != nil {
				logger.Info("service did not register a connect-rpc handler", slog.String("namespace", ns))
			}

			// Register In Process Connect RPC Services
			if err := svc.RegisterConnectRPCServiceHandler(ctx, otdf.ConnectRPCInProcess.ConnectRPC); err != nil {
				logger.Info("service did not register a connect-rpc handler", slog.String("namespace", ns))
			}

			// Register GRPC Gateway Handler using the in-process connect rpc
			grpcConn := otdf.ConnectRPCInProcess.GrpcConn()
			err := svc.RegisterGRPCGatewayHandler(ctx, otdf.GRPCGatewayMux, otdf.ConnectRPCInProcess.GrpcConn())
			if err != nil {
				logger.Info("service did not register a grpc gateway handler", slog.String("namespace", ns))
			} else if gatewayCleanup == nil {
				gatewayCleanup = func() {
					slog.Debug("executing cleanup")
					if grpcConn != nil {
						grpcConn.Close()
					}
					slog.Info("cleanup complete")
				}
			}

			// Register Extra Handlers
			if err := svc.RegisterHTTPHandlers(ctx, otdf.GRPCGatewayMux); err != nil {
				logger.Info("service did not register extra http handlers", slog.String("namespace", ns))
			}

			logger.Info(
				"service running",
				slog.String("namespace", ns),
				slog.String("service", svc.GetServiceDesc().ServiceName),
				slog.Group("database",
					slog.Any("required", svcDBClient != nil),
					slog.Any("migrationStatus", determineStatusOfMigration(svcDBClient)),
				),
			)
		}
	}

	if gatewayCleanup == nil {
		gatewayCleanup = func() {}
	}
	return gatewayCleanup, nil
}

func extractServiceLoggerConfig(cfg config.ServiceConfig) (string, error) {
	type ServiceConfigWithLogger struct {
		LogLevel string `mapstructure:"log_level" json:"log_level,omitempty"`
	}
	var svcLoggerConfig ServiceConfigWithLogger
	err := mapstructure.Decode(cfg, &svcLoggerConfig)
	if err == nil && svcLoggerConfig.LogLevel != "" {
		return svcLoggerConfig.LogLevel, nil
	}
	return "", fmt.Errorf("could not decode service log level: %w", err)
}

// newServiceDBClient creates a new database client for the specified namespace.
// It initializes the client with the provided context, logger configuration, database configuration,
// namespace, and migrations. It returns the created client and any error encountered during creation.
func newServiceDBClient(ctx context.Context, logCfg logging.Config, dbCfg db.Config, trace trace.Tracer, ns string, migrations *embed.FS) (*db.Client, error) {
	var err error

	client, err := db.New(ctx, dbCfg, logCfg, &trace,
		db.WithService(ns),
		db.WithMigrations(migrations),
	)
	if err != nil {
		return nil, fmt.Errorf("issue creating database client for %s: %w", ns, err)
	}

	return client, nil
}

// determineStatusOfMigration determines the status of the migration based on the provided client.
// It checks if the client is required, if the required migrations have already been ran,
// if the service does not require a database, or if the migrations are disabled.
// It returns a string indicating the reason for the determined status.
func determineStatusOfMigration(client *db.Client) string {
	required := (client != nil)
	requiredAlreadyRan := required && client.MigrationsEnabled() && client.RanMigrations()
	noDBRequired := !required
	migrationsDisabled := (required && !client.MigrationsEnabled())

	reason := "undetermined"
	switch {
	case requiredAlreadyRan:
		reason = "required migrations already ran"
	case noDBRequired:
		reason = "service does not require a database"
	case migrationsDisabled:
		reason = "migrations are disabled"
	}
	return reason
}
