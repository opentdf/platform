package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/opentdf/platform/internal/config"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/logger"
	"github.com/opentdf/platform/internal/opa"
	"github.com/opentdf/platform/internal/server"
	"github.com/opentdf/platform/pkg/serviceregistry"
	wellknown "github.com/opentdf/platform/services/wellknownconfiguration"
)

type StartOptions func(StartConfig) StartConfig

func WithConfigName(name string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigName = name
		return c
	}
}

func WithWaitForShutdownSignal() StartOptions {
	return func(c StartConfig) StartConfig {
		c.WaitForShutdownSignal = true
		return c
	}
}

type StartConfig struct {
	ConfigName            string
	WaitForShutdownSignal bool
}

func Start(f ...StartOptions) error {
	startConfig := StartConfig{}
	for _, fn := range f {
		startConfig = fn(startConfig)
	}

	slog.Info("starting opentdf services")

	// Load the config
	conf, err := config.LoadConfig(startConfig.ConfigName)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	logger, err := logger.NewLogger(conf.Logger)
	if err != nil {
		return fmt.Errorf("could not start logger: %w", err)
	}
	slog.SetDefault(logger.Logger)

	ctx := context.Background()

	slog.Info("starting opa engine")
	// Start the opa engine
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		return fmt.Errorf("could not start opa engine: %w", err)
	}
	defer eng.Stop(ctx)

	// Lets make sure we can establish a new db client
	dbClient, err := createDatabaseClient(ctx, conf.DB)
	if err != nil {
		return fmt.Errorf("issue creating database client: %w", err)
	}
	defer dbClient.Close()

	// Create new server for grpc & http. Also will support in process grpc potentially too
	otdf, err := server.NewOpenTDFServer(conf.Server)
	if err != nil {
		slog.Error("issue creating opentdf server", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating opentdf server: %w", err)
	}
	defer otdf.Stop()

	slog.Info("registering services")
	if err := registerServices(); err != nil {
		slog.Error("issue registering services", slog.String("error", err.Error()))
		return fmt.Errorf("issue registering services: %w", err)
	}

	slog.Info("starting services")
	if err := startServices(*conf, otdf, dbClient, eng); err != nil {
		slog.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}

	// Start the server
	slog.Info("starting opentdf")

	otdf.Run()

	if startConfig.WaitForShutdownSignal {
		waitForShutdownSignal()
	}

	return nil
}

// waitForShutdownSignal blocks until a SIGINT or SIGTERM is received.
func waitForShutdownSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func createDatabaseClient(ctx context.Context, conf db.Config) (*db.Client, error) {
	slog.Info("creating database client")
	dbClient, err := db.NewClient(conf)
	if err != nil {
		//nolint:wrapcheck // we want to return the error as is. the start command will wrap it
		return nil, err
	}

	slog.Info("running database migrations")
	appliedMigrations, err := dbClient.RunMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("issue running database migrations: %w", err)
	}

	slog.Info("database migrations complete", slog.Int("applied", appliedMigrations))
	return dbClient, nil
}

func startServices(cfg config.Config, otdf *server.OpenTDFServer, dbClient *db.Client, eng *opa.Engine) error {
	// Iterate through the registered namespaces
	for ns, registers := range serviceregistry.RegisteredServices {
		// Check if the service is enabled
		if !cfg.Services[ns].Enabled {
			slog.Debug("start service skipped", slog.String("namespace", ns))
			continue
		}

		for _, r := range registers {
			// Create the service
			impl, handler := r.RegisterFunc(serviceregistry.RegistrationParams{
				Config:          cfg.Services[ns],
				OTDF:            otdf,
				DBClient:        dbClient,
				Engine:          eng,
				WellKnownConfig: wellknown.RegisterConfiguration,
			})

			// Register the service with the gRPC server
			otdf.GrpcServer.RegisterService(r.ServiceDesc, impl)

			// Register the service with the gRPC gateway
			if err := handler(context.Background(), otdf.Mux, impl); err != nil {
				slog.Error("failed to start service", slog.String("namespace", r.Namespace), slog.String("error", err.Error()))
				return err
			}

			slog.Info("started service", slog.String("namespace", ns), slog.String("service", r.ServiceDesc.ServiceName))
		}
	}

	return nil
}
