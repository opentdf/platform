package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/health"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/db"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/kas"
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

func startServices(ctx context.Context, cfg config.Config, otdf *server.OpenTDFServer, eng *opa.Engine, client *sdk.SDK) (func(), []serviceregistry.Service, error) {
	// CloseServices is a function that will close all registered services
	closeServices := func() {
		slog.Info("stopping services")
		for ns, registers := range serviceregistry.RegisteredServices {
			for _, r := range registers {
				// Only report on started services
				if !r.Started {
					continue
				}
				slog.Info("stopping service", slog.String("namespace", ns), slog.String("service", r.ServiceDesc.ServiceName))
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
			slog.Debug("start service skipped", slog.String("namespace", ns))
			continue
		}

		// Use a single database client per namespace
		var d *db.Client

		for _, r := range registers {
			s, err := startService(ctx, cfg, r, otdf, eng, client, d)
			if err != nil {
				return closeServices, services, err
			}
			services = append(services, s)
		}
	}

	return closeServices, services, nil
}

func startService(ctx context.Context, cfg config.Config, s serviceregistry.Service, otdf *server.OpenTDFServer, eng *opa.Engine, client *sdk.SDK, d *db.Client) (serviceregistry.Service, error) {
	// Create the database client if required
	if s.DB.Required && d == nil {
		var err error

		// Conditionally set the db client if the service requires it
		// Currently, we are dynamically registering namespaces and don't offer the ability to apply
		// config at the NS layer. This poses a problem where services under a NS want to share a
		// database connection.
		// TODO: this should be reassessed with how we handle registering a single namespace
		slog.Info("creating database client", slog.String("namespace", s.Namespace))
		// Make sure we only create a single db client per namespace
		d, err = db.New(ctx, cfg.DB,
			db.WithService(s.Namespace),
			db.WithMigrations(s.DB.Migrations),
		)
		if err != nil {
			return s, fmt.Errorf("issue creating database client for %s: %w", s.Namespace, err)
		}
	}

	// Run migrations if required
	if cfg.DB.RunMigrations && d != nil {
		if s.DB.Migrations == nil {
			return s, fmt.Errorf("migrations FS is required when runMigrations is enabled")
		}

		slog.Info("running database migrations")
		appliedMigrations, err := d.RunMigrations(ctx, s.DB.Migrations)
		if err != nil {
			return s, fmt.Errorf("issue running database migrations: %w", err)
		}
		slog.Info("database migrations complete",
			slog.Int("applied", appliedMigrations),
		)
	} else {
		slog.Info("skipping migrations",
			slog.String("namespace", s.Namespace),
			slog.String("reason", "runMigrations is false"),
			slog.Bool("runMigrations", false),
		)
	}

	// Create the service
	impl, handler := s.RegisterFunc(serviceregistry.RegistrationParams{
		Config:          cfg.Services[s.Namespace],
		OTDF:            otdf,
		DBClient:        d,
		Engine:          eng,
		SDK:             client,
		WellKnownConfig: wellknown.RegisterConfiguration,
	})

	// Register the service with the gRPC server
	otdf.GRPCServer.RegisterService(s.ServiceDesc, impl)

	// Register the service with in process gRPC server
	otdf.GRPCInProcess.GetGrpcServer().RegisterService(s.ServiceDesc, impl)

	// Register the service with the gRPC gateway
	if err := handler(ctx, otdf.Mux, impl); err != nil {
		slog.Error("failed to start service", slog.String("namespace", s.Namespace), slog.String("error", err.Error()))
		return s, err
	}

	slog.Info("started service", slog.String("namespace", s.Namespace), slog.String("service", s.ServiceDesc.ServiceName))
	s.Started = true
	s.Close = func() {
		if d != nil {
			slog.Info("closing database client", slog.String("namespace", s.Namespace), slog.String("service", s.ServiceDesc.ServiceName))
			// TODO: this might be a problem if we can't call close on the db client multiple times
			d.Close()
		}
	}
	return s, nil
}
