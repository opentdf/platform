package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/health"
	"github.com/opentdf/platform/service/internal/db"
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

func registerServiceDb(ctx context.Context, cfg db.Config, svc serviceregistry.Service, d *db.Client) error {
	reg := svc.Registration
	// If the service doesn't require a db client, return
	if !reg.DB.Required {
		return nil
	}

	// If the db client is already set, return
	if d != nil {
		return nil
	}

	// Conditionally set the db client if the service requires it
	// Currently, we are dynamically registering namespaces and don't offer the ability to apply
	// config at the NS layer. This poses a problem where services under a NS want to share a
	// database connection.
	// TODO: this should be reassessed with how we handle registering a single namespace

	slog.Info("creating database client", slog.String("namespace", reg.Namespace))
	// Make sure we only create a single db client per namespace
	var err error
	d, err = db.New(cfg,
		db.WithService(reg.Namespace),
		db.WithVerifyConnection(),
		db.WithMigrations(reg.DB.Migrations),
	)
	if err != nil {
		return fmt.Errorf("issue creating database client for %s: %w", reg.Namespace, err)
	}

	// Run migrations if required
	if cfg.RunMigrations {
		if reg.DB.Migrations == nil {
			return fmt.Errorf("migrations FS is required when runMigrations is true")
		}

		slog.Info("running database migrations")
		appliedMigrations, err := d.RunMigrations(ctx, reg.DB.Migrations)
		if err != nil {
			return fmt.Errorf("issue running database migrations: %w", err)
		}
		slog.Info("database migrations complete",
			slog.Int("applied", appliedMigrations),
		)
	} else {
		slog.Info("skipping migrations",
			slog.String("reason", "runMigrations is false"),
			slog.Bool("runMigrations", false),
		)
	}
	return nil
}
