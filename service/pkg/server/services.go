package server

import (
	"context"
	"embed"
	"fmt"
	"log/slog"

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

var (
	ServiceHealth           ServiceName = "health"
	ServiceKAS              ServiceName = "kas"
	ServicePolicy           ServiceName = "policy"
	ServiceWellKnown        ServiceName = "wellknown"
	ServiceEntityResolution ServiceName = "entityresolution"
	ServiceAuthorization    ServiceName = "authorization"
)

// getServiceConfigurations returns fresh service configurations each time it's called.
// This prevents state sharing between test runs by creating new service instances.
func getServiceConfigurations() []serviceregistry.ServiceConfiguration {
	return []serviceregistry.ServiceConfiguration{
		{
			Name:     ServiceHealth,
			Modes:    []serviceregistry.ModeName{serviceregistry.ModeEssential},
			Services: []serviceregistry.IService{health.NewRegistration()},
		},
		{
			Name:     ServicePolicy,
			Modes:    []serviceregistry.ModeName{serviceregistry.ModeALL, serviceregistry.ModeCore},
			Services: policy.NewRegistrations(),
		},
		{
			Name:     ServiceAuthorization,
			Modes:    []serviceregistry.ModeName{serviceregistry.ModeALL, serviceregistry.ModeCore},
			Services: []serviceregistry.IService{authorization.NewRegistration(), authorizationV2.NewRegistration()},
		},
		{
			Name:     ServiceKAS,
			Modes:    []serviceregistry.ModeName{serviceregistry.ModeALL, serviceregistry.ModeKAS},
			Services: []serviceregistry.IService{kas.NewRegistration()},
		},
		{
			Name:     ServiceWellKnown,
			Modes:    []serviceregistry.ModeName{serviceregistry.ModeALL, serviceregistry.ModeCore},
			Services: []serviceregistry.IService{wellknown.NewRegistration()},
		},
		{
			Name:     ServiceEntityResolution,
			Modes:    []serviceregistry.ModeName{serviceregistry.ModeALL, serviceregistry.ModeERS},
			Services: []serviceregistry.IService{entityresolution.NewRegistration(), entityresolutionV2.NewRegistration()},
		},
	}
}

// ServiceName represents a typed service identifier
type ServiceName string

// String returns the string representation of ServiceName
func (s ServiceName) String() string {
	return string(s)
}

// RegisterEssentialServices registers the essential services directly
func RegisterEssentialServices(reg serviceregistry.Registry) error {
	essentialServices := []serviceregistry.IService{
		health.NewRegistration(),
	}

	for _, svc := range essentialServices {
		if err := reg.RegisterService(svc, serviceregistry.ModeEssential); err != nil {
			return err
		}
	}
	return nil
}

// RegisterCoreServices registers the core services using declarative configuration
func RegisterCoreServices(reg serviceregistry.Registry, modes []serviceregistry.ModeName) ([]string, error) {
	return reg.RegisterServicesFromConfiguration(modes, getServiceConfigurations())
}

type startServicesParams struct {
	cfg                 *config.Config
	otdf                *server.OpenTDFServer
	client              *sdk.SDK
	logger              *logging.Logger
	reg                 *serviceregistry.Registry
	cacheManager        *cache.Manager
	keyManagerFactories []trust.NamedKeyManagerFactory
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
	keyManagerFactories := params.keyManagerFactories

	// Iterate through the registered namespaces
	for ns, namespace := range reg {
		// Check if this namespace should be enabled based on configured modes
		modeEnabled := namespace.IsEnabled(cfg.Mode)

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
