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
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
)

// We always want to register the essential services. Even if only a pep like kas is running.
func registerEssentialServices(reg serviceregistry.Registry) error {
	essentialServices := []serviceregistry.Registration{
		health.NewRegistration(),
	}
	// Register the essential services
	for _, s := range essentialServices {
		if err := reg.RegisterService(s, "essential"); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}

func registerCoreServices(reg serviceregistry.Registry, mode []string) ([]string, error) {
	var (
		services           []serviceregistry.Registration
		registeredServices []string
	)
	for _, m := range mode {
		switch m {
		case "all":
			registeredServices = append(registeredServices, []string{"policy", "authorization", "kas", "wellknown", "entityresolution"}...)
			services = append(services, []serviceregistry.Registration{
				authorization.NewRegistration(),
				kas.NewRegistration(),
				wellknown.NewRegistration(),
				entityresolution.NewRegistration(),
			}...)
			services = append(services, policy.NewRegistrations()...)
		case "core":
			registeredServices = append(registeredServices, []string{"policy", "authorization", "wellknown"}...)
			services = append(services, []serviceregistry.Registration{
				entityresolution.NewRegistration(),
				authorization.NewRegistration(),
				wellknown.NewRegistration(),
			}...)
			services = append(services, policy.NewRegistrations()...)
		case "kas":
			registeredServices = append(registeredServices, "kas")
			services = append(services, kas.NewRegistration())
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

func startServices(ctx context.Context, cfg config.Config, otdf *server.OpenTDFServer, client *sdk.SDK, logger *logger.Logger, reg serviceregistry.Registry) error {
	// Iterate through the registered namespaces
	for ns, namespace := range reg {
		modeEnabled := slices.ContainsFunc(cfg.Mode, func(m string) bool {
			if strings.EqualFold(m, "all") || strings.EqualFold(m, "essential") {
				return true
			}
			return strings.EqualFold(m, namespace.Mode)
		})
		fmt.Println(modeEnabled, namespace.Mode)
		if !modeEnabled {
			logger.Info("skipping namespace", slog.String("namespace", ns), slog.String("mode", namespace.Mode))
			continue
		}

		svcLogger := logger.With("namespace", ns)

		// Create new service logger
		var svcDBClient *db.Client
		for _, svc := range namespace.Services {

			// Get new db client if needed
			if svc.DB.Required && svcDBClient == nil {
				var err error
				svcDBClient, err = newServiceDBClient(ctx, cfg.Logger, cfg.DB, ns, svc.DB.Migrations)
				if err != nil {
					return err
				}
			}

			err := svc.Start(serviceregistry.RegistrationParams{
				Config:                 cfg.Services[svc.Namespace],
				Logger:                 svcLogger,
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
			svc.RegisterGRPCServer(otdf.GRPCServer)

			// Register the service with in process gRPC server
			svc.RegisterGRPCServer(otdf.GRPCInProcess.GetGrpcServer())

			// Register the service with the gRPC gateway
			if err := svc.RegisterHTTPServer(ctx, otdf.Mux); err != nil {
				logger.Error("failed to register service to grpc gateway", slog.String("namespace", ns), slog.String("error", err.Error()))
				return err
			}

			logger.Info(
				"service running",
				slog.String("namespace", ns),
				slog.String("service", svc.ServiceDesc.ServiceName),
				slog.Bool("database", svc.DB.Required),
			)

		}
	}

	return nil
}

func newServiceDBClient(ctx context.Context, logCfg logger.Config, dbCfg db.Config, ns string, migrations *embed.FS) (*db.Client, error) {
	var err error

	slog.Info("creating database client", slog.String("namespace", ns))
	client, err := db.New(ctx, dbCfg, logCfg,
		db.WithService(ns),
		db.WithMigrations(migrations),
	)
	if err != nil {
		return nil, fmt.Errorf("issue creating database client for %s: %w", ns, err)
	}

	return client, nil
}
