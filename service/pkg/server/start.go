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
	"github.com/opentdf/platform/service/internal/server"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
)

const devModeMessage = `
██████╗ ███████╗██╗   ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗███╗   ██╗████████╗    ███╗   ███╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██║   ██║██╔════╝██║     ██╔═══██╗██╔══██╗████╗ ████║██╔════╝████╗  ██║╚══██╔══╝    ████╗ ████║██╔═══██╗██╔══██╗██╔════╝
██║  ██║█████╗  ██║   ██║█████╗  ██║     ██║   ██║██████╔╝██╔████╔██║█████╗  ██╔██╗ ██║   ██║       ██╔████╔██║██║   ██║██║  ██║█████╗  
██║  ██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║     ██║   ██║██╔═══╝ ██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║       ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝  
██████╔╝███████╗ ╚████╔╝ ███████╗███████╗╚██████╔╝██║     ██║ ╚═╝ ██║███████╗██║ ╚████║   ██║       ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝                                                                                        
`

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

	if conf.DevMode {
		fmt.Print(devModeMessage) //nolint:forbidigo // This ascii art is only displayed in dev mode
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

	// Set default for places we can't pass the logger
	slog.SetDefault(logger.Logger)

	logger.Debug("config loaded", slog.Any("config", conf))

	// Required services
	conf.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration

	// Create new server for grpc & http. Also will support in process grpc potentially too
	logger.Info("init opentdf server")
	conf.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration
	otdf, err := server.NewOpenTDFServer(conf.Server, logger)
	if err != nil {
		logger.Error("issue creating opentdf server", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating opentdf server: %w", err)
	}
	defer otdf.Stop()

	logger.Info("registering services")
	if err := registerServices(); err != nil {
		logger.Error("issue registering services", slog.String("error", err.Error()))
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

	// Use IPC for the SDK client
	sdkOptions = append(sdkOptions, sdk.WithIPC())

	client, err := sdk.New("", sdkOptions...)
	if err != nil {
		logger.Error("issue creating sdk client", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating sdk client: %w", err)
	}
	defer client.Close()

	logger.Info("starting services")
	closeServices, services, err := startServices(ctx, *conf, otdf, client, logger)
	if err != nil {
		logger.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}
	defer closeServices()

	// Start the server
	logger.Info("starting opentdf")
	otdf.Start()

	// Print out the registered services
	logger.Info("services running")
	for _, service := range services {
		logger.Info(
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
