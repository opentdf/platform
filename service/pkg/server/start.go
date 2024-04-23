package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/db"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
)

type StartOptions func(StartConfig) StartConfig

// Deprecated: Use WithConfigKey
func WithConfigName(name string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigKey = name
		return c
	}
}

func WithConfigFile(file string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigFile = file
		return c
	}
}

func WithConfigKey(key string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigKey = key
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
	ConfigKey             string
	ConfigFile            string
	WaitForShutdownSignal bool
}

func Start(f ...StartOptions) error {
	startConfig := StartConfig{}
	for _, fn := range f {
		startConfig = fn(startConfig)
	}

	ctx := context.Background()

	slog.Info("starting opentdf services")

	slog.Info("loading configuration")
	conf, err := config.LoadConfig(startConfig.ConfigKey, startConfig.ConfigFile)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	slog.Info("starting logger")
	logger, err := logger.NewLogger(conf.Logger)
	if err != nil {
		return fmt.Errorf("could not start logger: %w", err)
	}
	slog.SetDefault(logger.Logger)

	slog.Debug("config loaded", slog.Any("config", conf))

	slog.Info("starting opa engine")
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		return fmt.Errorf("could not start opa engine: %w", err)
	}
	defer eng.Stop(ctx)

	// Required services
	conf.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration

	// Create new server for grpc & http. Also will support in process grpc potentially too
	slog.Info("init opentdf server")
	conf.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration
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

	// Create the SDK client for services to use
	var sdkOptions []sdk.Option
	for name, service := range conf.Services {
		if service.Remote.Endpoint == "" && service.Enabled {
			switch name {
			case "policy":
				sdkOptions = append(sdkOptions, sdk.WithCustomPolicyConnection(otdf.GRPCInProcess.Conn()))
			case "authorization":
				sdkOptions = append(sdkOptions, sdk.WithCustomAuthorizationConnection(otdf.GRPCInProcess.Conn()))
			}
		}
	}

	client, err := sdk.New("", sdkOptions...)
	if err != nil {
		slog.Error("issue creating sdk client", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating sdk client: %w", err)
	}
	defer client.Close()

	slog.Info("starting services")
	closeServices, err := startServices(*conf, otdf, eng, client)
	if err != nil {
		slog.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}
	defer closeServices()

	// Start the server
	slog.Info("starting opentdf")
	otdf.Start()

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

func startServices(cfg config.Config, otdf *server.OpenTDFServer, eng *opa.Engine, client *sdk.SDK) (func(), error) {
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

	// Iterate through the registered namespaces
	for ns, registers := range serviceregistry.RegisteredServices {
		// Check if the service is enabled
		if !cfg.Services[ns].Enabled {
			slog.Debug("start service skipped", slog.String("namespace", ns))
			continue
		}

		var d *db.Client
		// Conditionally set the db client if the service requires it

		for _, r := range registers {

			// Conditionally set the db client if the service requires it
			// Currently, we are dynamically registering namespaces and don't offer the ability to apply
			// config at the NS layer. This poses a problem where services under a NS want to share a
			// database connection.
			// TODO: this should be reassessed with how we handle registering a single namespace
			if r.DB.Required && d == nil {
				slog.Info("creating database client", slog.String("namespace", ns))
				// Make sure we only create a single db client per namespace
				var err error
				d, err = db.New(cfg.DB,
					db.WithService(ns),
					db.WithVerifyConnection(),
					db.WithMigrations(r.DB.Migrations),
				)
				if err != nil {
					return closeServices, fmt.Errorf("issue creating database client for %s: %w", ns, err)
				}

				// Run migrations if required
				if cfg.DB.RunMigrations {
					if r.DB.Migrations == nil {
						return closeServices, fmt.Errorf("migrations FS is required when runMigrations is true")
					}

					slog.Info("running database migrations")
					appliedMigrations, err := d.RunMigrations(context.Background(), r.DB.Migrations)
					if err != nil {
						return nil, fmt.Errorf("issue running database migrations: %w", err)
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
			}

			// Create the service
			impl, handler := r.RegisterFunc(serviceregistry.RegistrationParams{
				Config:          cfg.Services[ns],
				OTDF:            otdf,
				DBClient:        d,
				Engine:          eng,
				SDK:             client,
				WellKnownConfig: wellknown.RegisterConfiguration,
			})

			// Register the service with the gRPC server
			otdf.GRPCServer.RegisterService(r.ServiceDesc, impl)

			// Register the service with in process gRPC server
			otdf.GRPCInProcess.GetGrpcServer().RegisterService(r.ServiceDesc, impl)

			// Register the service with the gRPC gateway
			if err := handler(context.Background(), otdf.Mux, impl); err != nil {
				slog.Error("failed to start service", slog.String("namespace", r.Namespace), slog.String("error", err.Error()))
				return closeServices, err
			}

			slog.Info("started service", slog.String("namespace", ns), slog.String("service", r.ServiceDesc.ServiceName))
			r.Started = true
			r.Close = func() {
				if d != nil {
					slog.Info("closing database client", slog.String("namespace", ns), slog.String("service", r.ServiceDesc.ServiceName))
					// TODO: this might be a problem if we can't call close on the db client multiple times
					d.Close()
				}
			}
		}
	}

	return closeServices, nil
}
