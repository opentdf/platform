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
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/internal/opa"
	"github.com/opentdf/platform/service/internal/server"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
)

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

	// Set allowed public routes when platform is being extended
	if len(startConfig.PublicRoutes) > 0 {
		conf.Server.Auth.PublicRoutes = startConfig.PublicRoutes
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
			case "entityresolution":
				sdkOptions = append(sdkOptions, sdk.WithCustomEntityResolutionConnection(otdf.GRPCInProcess.Conn()))
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
	closeServices, services, err := startServices(ctx, *conf, otdf, eng, client, logger)
	if err != nil {
		slog.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}
	defer closeServices()

	// Start the server
	slog.Info("starting opentdf")
	otdf.Start()

	// Print out the registered services
	slog.Info("services running")
	for _, service := range services {
		slog.Info(
			"service running",
			slog.String("namespace", service.Registration.Namespace),
			slog.String("service", service.ServiceDesc.ServiceName),
			slog.Bool("database", service.Registration.DB.Required),
		)
	}

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
