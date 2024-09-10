package server

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/entityresolution"
	"github.com/opentdf/platform/service/health"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/kas"
	"github.com/opentdf/platform/service/logger"
	logging "github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
)

const (
	modeALL       = "all"
	modeCore      = "core"
	modeKAS       = "kas"
	modeEssential = "essential"

	serviceKAS              = "kas"
	servicePolicy           = "policy"
	serviceWellKnown        = "wellknown"
	serviceEntityResolution = "entityresolution"
	serviceAuthorization    = "authorization"
)

// registerEssentialServices registers the essential services to the given service registry.
// It takes a serviceregistry.Registry as input and returns an error if registration fails.
func registerEssentialServices(reg serviceregistry.Registry) error {
	essentialServices := []serviceregistry.Registration{
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
func registerCoreServices(reg serviceregistry.Registry, mode []string) ([]string, error) {
	var (
		services           []serviceregistry.Registration
		registeredServices []string
	)

	for _, m := range mode {
		switch m {
		case "all":
			registeredServices = append(registeredServices, []string{servicePolicy, serviceAuthorization, serviceKAS, serviceWellKnown, serviceEntityResolution}...)
			services = append(services, []serviceregistry.Registration{
				authorization.NewRegistration(),
				kas.NewRegistration(),
				wellknown.NewRegistration(),
				entityresolution.NewRegistration(),
			}...)
			services = append(services, policy.NewRegistrations()...)
		case "core":
			registeredServices = append(registeredServices, []string{servicePolicy, serviceAuthorization, serviceWellKnown}...)
			services = append(services, []serviceregistry.Registration{
				entityresolution.NewRegistration(),
				authorization.NewRegistration(),
				wellknown.NewRegistration(),
			}...)
			services = append(services, policy.NewRegistrations()...)
		case "kas":
			// If the mode is "kas", register only the KAS service
			registeredServices = append(registeredServices, serviceKAS)
			if err := reg.RegisterService(kas.NewRegistration(), modeKAS); err != nil {
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

// startServices iterates through the registered namespaces and starts the services
// based on the configuration and namespace mode. It creates a new service logger
// and a database client if required. It registers the services with the gRPC server,
// in-process gRPC server, and gRPC gateway. Finally, it logs the status of each service.
func startServices(ctx context.Context, cfg config.Config, otdf *server.OpenTDFServer, client *sdk.SDK, logger *logger.Logger, reg serviceregistry.Registry) error {
	// Iterate through the registered namespaces
	for ns, namespace := range reg {
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
			logger.Info("skipping namespace", slog.String("namespace", ns), slog.String("mode", namespace.Mode))
			continue
		}

		svcLogger := logger.With("namespace", ns)

		var svcDBClient *db.Client

		// Create new service logger
		for _, svc := range namespace.Services {
			var thisSvcLogger = svcLogger

			// Get new db client if it is required and not already created
			if svc.DB.Required && svcDBClient == nil {
				logger.Debug("creating database client", slog.String("namespace", ns))
				var err error
				svcDBClient, err = newServiceDBClient(ctx, cfg.Logger, cfg.DB, ns, svc.DB.Migrations)
				if err != nil {
					return err
				}
			}

			// If the service provides its own logging config, create a new logger for that service using that config
			if cfg.Services[svc.Namespace].Logger.Level != "" && cfg.Services[svc.Namespace].Logger.Output != "" && cfg.Services[svc.Namespace].Logger.Type != "" {
				slog.Debug("configuring logger")
				newSvcLogger, err := logging.NewLogger(cfg.Services[svc.Namespace].Logger)
				if err != nil {
					return fmt.Errorf("could not start logger: %w", err)
				}
				thisSvcLogger = newSvcLogger.With("namespace", ns)
			}

			err := svc.Start(ctx, serviceregistry.RegistrationParams{
				Config:                 cfg.Services[svc.Namespace].Extras,
				Logger:                 thisSvcLogger,
				DBClient:               svcDBClient,
				SDK:                    client,
				WellKnownConfig:        wellknown.RegisterConfiguration,
				RegisterReadinessCheck: health.RegisterReadinessCheck,
				OTDF:                   otdf, // TODO: REMOVE THIS
			})
			if err != nil {
				return err
			}
			// Register the service with the gRPC server
			if err := svc.RegisterGRPCServer(otdf.GRPCServer); err != nil {
				return err
			}

			// Register the service with in process gRPC server
			if err := svc.RegisterGRPCServer(otdf.GRPCInProcess.GetGrpcServer()); err != nil {
				return err
			}

			// Register the service with the gRPC gateway
			if err := svc.RegisterHTTPServer(ctx, otdf.Mux); err != nil { //nolint:staticcheck // This is deprecated for internal tracking
				logger.Error("failed to register service to grpc gateway", slog.String("namespace", ns), slog.String("error", err.Error()))
				return err
			}

			logger.Info(
				"service running",
				slog.String("namespace", ns),
				slog.String("service", svc.ServiceDesc.ServiceName),
				slog.Group("database",
					slog.Any("required", svcDBClient != nil),
					slog.Any("migrationStatus", determineStatusOfMigration(svcDBClient)),
				),
			)
		}
	}

	return nil
}

func tryExtractingServiceLoggerConfig(cfg serviceregistry.ServiceConfigWithLogger) (logger.Config, error) {
	// var svcLoggerConfig logger.Config
	// err := mapstructure.Decode(cfg, &svcLoggerConfig)
	if cfg.Logger.Level != "" && cfg.Logger.Output != "" && cfg.Logger.Type != "" {
		return cfg.Logger, nil
	}
	return cfg.Logger, fmt.Errorf("could not decode service logger config")
}

// newServiceDBClient creates a new database client for the specified namespace.
// It initializes the client with the provided context, logger configuration, database configuration,
// namespace, and migrations. It returns the created client and any error encountered during creation.
func newServiceDBClient(ctx context.Context, logCfg logger.Config, dbCfg db.Config, ns string, migrations *embed.FS) (*db.Client, error) {
	var err error

	client, err := db.New(ctx, dbCfg, logCfg,
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
