package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
	"golang.org/x/exp/slices"
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

	slog.Debug("loading configuration")
	cfg, err := config.LoadConfig(startConfig.ConfigKey, startConfig.ConfigFile)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	if cfg.DevMode {
		fmt.Print(devModeMessage) //nolint:forbidigo // This ascii art is only displayed in dev mode
	}

	slog.Debug("configuring logger")
	logger, err := logger.NewLogger(cfg.Logger)
	if err != nil {
		return fmt.Errorf("could not start logger: %w", err)
	}

	// Set default for places we can't pass the logger
	slog.SetDefault(logger.Logger)

	logger.Info("starting opentdf services")

	// Set allowed public routes when platform is being extended
	if len(startConfig.PublicRoutes) > 0 {
		logger.Info("additional public routes added", slog.Any("routes", startConfig.PublicRoutes))
		cfg.Server.Auth.PublicRoutes = startConfig.PublicRoutes
	}

	logger.Debug("config loaded", slog.Any("config", cfg))

	// Create new server for grpc & http. Also will support in process grpc potentially too
	logger.Debug("initializing opentdf server")
	cfg.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration
	otdf, err := server.NewOpenTDFServer(cfg.Server, logger)
	if err != nil {
		logger.Error("issue creating opentdf server", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating opentdf server: %w", err)
	}
	defer otdf.Stop()

	// Append the authz policies
	if len(startConfig.authzDefaultPolicyExtension) > 0 {
		if otdf.AuthN == nil {
			err := errors.New("authn not enabled")
			logger.Error("issue adding authz policies", "error", err)
			return fmt.Errorf("issue adding authz policies: %w", err)
		}
		err := otdf.AuthN.ExtendAuthzDefaultPolicy(startConfig.authzDefaultPolicyExtension)
		if err != nil {
			logger.Error("issue adding authz policies", slog.String("error", err.Error()))
			return fmt.Errorf("issue adding authz policies: %w", err)
		}
	}

	// Initialize the service registry
	logger.Debug("initializing service registry")
	svcRegistry := serviceregistry.NewServiceRegistry()
	defer svcRegistry.Shutdown()

	// Register essential services every service needs (e.g. health check)
	logger.Debug("registering essential services")
	if err := registerEssentialServices(svcRegistry); err != nil {
		logger.Error("could not register essential services", slog.String("error", err.Error()))
		return fmt.Errorf("could not register essential services: %w", err)
	}

	logger.Debug("registering services")

	var registeredCoreServices []string

	registeredCoreServices, err = registerCoreServices(svcRegistry, cfg.Mode)
	if err != nil {
		logger.Error("could not register core services", slog.String("error", err.Error()))
		return fmt.Errorf("could not register core services: %w", err)
	}

	// Register Extra Core Services
	if len(startConfig.extraCoreServices) > 0 {
		logger.Debug("registering extra core services")
		for _, service := range startConfig.extraCoreServices {
			err := svcRegistry.RegisterCoreService(service)
			if err != nil {
				logger.Error("could not register extra core service", slog.String("error", err.Error()))
				return fmt.Errorf("could not register extra core service: %w", err)
			}
		}
	}

	// Register extra services
	if len(startConfig.extraServices) > 0 {
		logger.Debug("registering extra services")
		for _, service := range startConfig.extraServices {
			err := svcRegistry.RegisterService(service, service.Namespace)
			if err != nil {
				logger.Error("could not register extra service", slog.String("namespace", service.Namespace), slog.String("error", err.Error()))
				return fmt.Errorf("could not register extra service: %w", err)
			}
		}
	}

	logger.Info("registered the following core services", slog.Any("core_services", registeredCoreServices))

	var (
		sdkOptions []sdk.Option
		client     *sdk.SDK
	)

	// If the mode is not all or core, we need to have a valid SDK config
	if !slices.Contains(cfg.Mode, "all") && !slices.Contains(cfg.Mode, "core") && cfg.SDKConfig == (config.SDKConfig{}) {
		logger.Error("mode is not all or core, but no sdk config provided")
		return errors.New("mode is not all or core, but no sdk config provided")
	}

	// If client credentials are provided, use them
	if cfg.SDKConfig.ClientID != "" && cfg.SDKConfig.ClientSecret != "" {
		sdkOptions = append(sdkOptions, sdk.WithClientCredentials(cfg.SDKConfig.ClientID, cfg.SDKConfig.ClientSecret, nil))
	}

	// If the mode is all, use IPC for the SDK client
	if slices.Contains(cfg.Mode, "all") || slices.Contains(cfg.Mode, "core") {
		// Use IPC for the SDK client
		sdkOptions = append(sdkOptions, sdk.WithIPC())
		sdkOptions = append(sdkOptions, sdk.WithCustomPolicyConnection(otdf.GRPCInProcess.Conn()))
		sdkOptions = append(sdkOptions, sdk.WithCustomAuthorizationConnection(otdf.GRPCInProcess.Conn()))
		sdkOptions = append(sdkOptions, sdk.WithCustomEntityResolutionConnection(otdf.GRPCInProcess.Conn()))

		client, err = sdk.New("", sdkOptions...)
		if err != nil {
			logger.Error("issue creating sdk client", slog.String("error", err.Error()))
			return fmt.Errorf("issue creating sdk client: %w", err)
		}
	} else {
		// Use the provided SDK config
		if cfg.SDKConfig.Plaintext {
			sdkOptions = append(sdkOptions, sdk.WithInsecurePlaintextConn())
		}
		client, err = sdk.New(cfg.SDKConfig.Endpoint, sdkOptions...)
		if err != nil {
			logger.Error("issue creating sdk client", slog.String("error", err.Error()))
			return fmt.Errorf("issue creating sdk client: %w", err)
		}
	}

	defer client.Close()

	logger.Info("starting services")
	err = startServices(ctx, *cfg, otdf, client, logger, svcRegistry)
	if err != nil {
		logger.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}

	// Start the server
	logger.Info("starting opentdf")
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
