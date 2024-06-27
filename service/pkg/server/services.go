package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/entityresolution"
	"github.com/opentdf/platform/service/health"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/kas"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
)

func registerServices() error {
	services := []serviceregistry.Registration{
		health.NewRegistration(),
		authorization.NewRegistration(),
		kas.NewRegistration(),
		wellknown.NewRegistration(),
		entityresolution.NewRegistration(),
	}
	services = append(services, policy.NewRegistrations()...)

	// Register the services
	for _, s := range services {
		if err := serviceregistry.RegisterService(s); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}

func startServices(ctx context.Context, cfg config.Config, otdf *server.OpenTDFServer, eng *opa.Engine, client *sdk.SDK, logger *logger.Logger) (func(), []serviceregistry.Service, error) {
	// CloseServices is a function that will close all registered services
	closeServices := func() {
		logger.Info("stopping services")
		for ns, registers := range serviceregistry.RegisteredServices {
			for _, r := range registers {
				// Only report on started services
				if !r.Started {
					continue
				}
				logger.Info("stopping service", slog.String("namespace", ns), slog.String("service", r.ServiceDesc.ServiceName))
				if r.Close != nil {
					r.Close()
				}
			}
		}
	}

	services := []serviceregistry.Service{}

	// Iterate through the registered namespaces
	for ns, registers := range serviceregistry.RegisteredServices {
		// Check if the service is enabled
		if !cfg.Services[ns].Enabled {
			logger.Debug("start service skipped", slog.String("namespace", ns))
			continue
		}

		// Use a single database client per namespace and run migrations once per namespace
		var d *db.Client
		runMigrations := cfg.DB.RunMigrations

		for _, r := range registers {
			s, db, err := startService(ctx, &cfg, r, otdf, eng, client, d, &runMigrations, logger)
			if err != nil {
				return closeServices, services, err
			}
			d = db
			services = append(services, s)
		}
	}

	return closeServices, services, nil
}

func startService(
	ctx context.Context,
	cfg *config.Config,
	s serviceregistry.Service,
	otdf *server.OpenTDFServer,
	eng *opa.Engine,
	client *sdk.SDK,
	d *db.Client,
	runMigrations *bool,
	logger *logger.Logger,
) (serviceregistry.Service, *db.Client, error) {
	// Create the database client only if required
	if s.DB.Required && d == nil {
		var err error

		logger.Info("creating database client", slog.String("namespace", s.Namespace))
		d, err = db.New(ctx, cfg.DB,
			db.WithService(s.Namespace),
			db.WithMigrations(s.DB.Migrations),
		)
		if err != nil {
			return s, d, fmt.Errorf("issue creating database client for %s: %w", s.Namespace, err)
		}
	}

	// Run migrations IFF a service requires it and they're configured to run but haven't run yet
	shouldRun := s.DB.Required && *runMigrations
	if shouldRun {
		logger.Info("running database migrations")
		appliedMigrations, err := d.RunMigrations(ctx, s.DB.Migrations)
		if err != nil {
			return s, d, fmt.Errorf("issue running database migrations: %w", err)
		}
		logger.Info("database migrations complete",
			slog.Int("applied", appliedMigrations),
		)
		// Only run migrations once
		*runMigrations = false
	}

	if !shouldRun {
		requiredAlreadyRan := s.DB.Required && cfg.DB.RunMigrations && !*runMigrations
		noDBRequired := !s.DB.Required
		migrationsDisabled := !cfg.DB.RunMigrations

		reason := "undetermined"
		if requiredAlreadyRan { //nolint:gocritic // This is more readable than a switch
			reason = "required migrations already ran"
		} else if noDBRequired {
			reason = "service does not require a database"
		} else if migrationsDisabled {
			reason = "migrations are disabled"
		}

		logger.Info("skipping migrations",
			slog.String("namespace", s.Namespace),
			slog.String("service", s.ServiceDesc.ServiceName),
			slog.Bool("configured runMigrations", cfg.DB.RunMigrations),
			slog.String("reason", reason),
		)
	}

	// Create the service
	impl, handler := s.RegisterFunc(serviceregistry.RegistrationParams{
		Config:                 cfg.Services[s.Namespace],
		OTDF:                   otdf,
		DBClient:               d,
		Engine:                 eng,
		SDK:                    client,
		WellKnownConfig:        wellknown.RegisterConfiguration,
		RegisterReadinessCheck: health.RegisterReadinessCheck,
		Logger:                 logger.With("namespace", s.Namespace),
	})

	// Register the service with the gRPC server
	otdf.GRPCServer.RegisterService(s.ServiceDesc, impl)

	// Register the service with in process gRPC server
	otdf.GRPCInProcess.GetGrpcServer().RegisterService(s.ServiceDesc, impl)

	// Register the service with the gRPC gateway
	if err := handler(ctx, otdf.Mux, impl); err != nil {
		logger.Error("failed to start service", slog.String("namespace", s.Namespace), slog.String("error", err.Error()))
		return s, d, err
	}

	logger.Info("started service", slog.String("namespace", s.Namespace), slog.String("service", s.ServiceDesc.ServiceName))
	s.Started = true
	s.Close = func() {
		if d != nil {
			logger.Info("closing database client", slog.String("namespace", s.Namespace), slog.String("service", s.ServiceDesc.ServiceName))
			// TODO: this might be a problem if we can't call close on the db client multiple times
			d.Close()
		}
	}
	return s, d, nil
}
