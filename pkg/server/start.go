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
	"github.com/opentdf/platform/sdk"
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

	ctx := context.Background()

	slog.Info("starting opentdf services")

	slog.Info("loading configuration")
	conf, err := config.LoadConfig(startConfig.ConfigName)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	slog.Info("starting logger")
	logger, err := logger.NewLogger(conf.Logger)
	if err != nil {
		return fmt.Errorf("could not start logger: %w", err)
	}
	slog.SetDefault(logger.Logger)

	slog.Info("starting opa engine")
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		return fmt.Errorf("could not start opa engine: %w", err)
	}
	defer eng.Stop(ctx)

	slog.Info("creating database client")
	dbClient, err := db.NewClient(conf.DB)
	if err != nil {
		return fmt.Errorf("issue creating database client: %w", err)
	}
	defer dbClient.Close()

	// Required services
	conf.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration

	// Create new server for grpc & http. Also will support in process grpc potentially too
	conf.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration
	otdf, err := server.NewOpenTDFServer(conf.Server, dbClient)
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
	if err := startServices(*conf, otdf, dbClient, eng, client); err != nil {
		slog.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}

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

func startServices(cfg config.Config, otdf *server.OpenTDFServer, dbClient *db.Client, eng *opa.Engine, client *sdk.SDK) error {
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
				return err
			}

			slog.Info("started service", slog.String("namespace", ns), slog.String("service", r.ServiceDesc.ServiceName))
		}
	}

	return nil
}
