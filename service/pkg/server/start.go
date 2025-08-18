package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/auth/oauth"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/tracing"
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
const dpopKeySize = 2048

func Start(f ...StartOptions) error {
	startConfig := StartConfig{}
	for _, fn := range f {
		startConfig = fn(startConfig)
	}

	ctx := context.Background()

	slog.Debug("loading configuration from environment")
	cfg, err := config.LoadConfig(ctx, startConfig.ConfigKey, startConfig.ConfigFile)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	if startConfig.configLoaders != nil {
		slog.Debug("loading configuration from additional provided loaders")

		for _, loader := range startConfig.configLoaders {
			slog.Debug("loading config for loader", slog.String("loader", loader.Name()))
			err := loader.Load(cfg)
			if err != nil {
				return fmt.Errorf("failed load config with loader %s: %w", loader.Name(), err)
			}
			cfg.AddLoader(loader)
		}
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

	// Initialize tracer
	logger.Debug("configuring otel tracer")
	shutdown, err := tracing.InitTracer(ctx, cfg.Server.Trace)
	if err != nil {
		return fmt.Errorf("could not initialize tracer: %w", err)
	}
	defer shutdown()

	logger.Debug("config loaded", slog.Any("config", cfg.LogValue()))

	// Configure cache manager
	logger.Info("creating cache manager")
	if cfg.Server.Cache.Driver != "ristretto" {
		return fmt.Errorf("unsupported cache driver: %s", cfg.Server.Cache.Driver)
	}
	cacheManager, err := cache.NewCacheManager(cfg.Server.Cache.RistrettoCache.MaxCostBytes())
	if err != nil {
		return fmt.Errorf("could not create cache manager: %w", err)
	}
	defer cacheManager.Close()

	logger.Info("starting opentdf services")

	// Set allowed public routes when platform is being extended
	if len(startConfig.PublicRoutes) > 0 {
		logger.Info("additional public routes added", slog.Any("routes", startConfig.PublicRoutes))
		cfg.Server.Auth.PublicRoutes = startConfig.PublicRoutes
	}

	// Set IPC reauthorization routes when platform is being extended
	if len(startConfig.IPCReauthRoutes) > 0 {
		logger.Info("additional IPC reauthorization routes added", slog.Any("routes", startConfig.IPCReauthRoutes))
		cfg.Server.Auth.IPCReauthRoutes = startConfig.IPCReauthRoutes
	}

	// Set Default Policy
	if startConfig.builtinPolicyOverride != "" {
		cfg.Server.Auth.Policy.Builtin = startConfig.builtinPolicyOverride
	}

	// Set Casbin Adapter
	if startConfig.casbinAdapter != nil {
		cfg.Server.Auth.Policy.Adapter = startConfig.casbinAdapter
	}

	// Create new server for grpc & http. Also will support in process grpc potentially too
	logger.Debug("initializing opentdf server")
	cfg.Server.WellKnownConfigRegister = wellknown.RegisterConfiguration
	otdf, err := server.NewOpenTDFServer(cfg.Server, logger, cacheManager)
	if err != nil {
		logger.Error("issue creating opentdf server", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating opentdf server: %w", err)
	}
	defer otdf.Stop()

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

	// Register extra services (only run in matching modes)
	if len(startConfig.extraServices) > 0 {
		logger.Debug("registering extra services")
		for _, service := range startConfig.extraServices {
			err := svcRegistry.RegisterService(service, service.GetNamespace())
			if err != nil {
				logger.Error("could not register extra service",
					slog.String("namespace", service.GetNamespace()),
					slog.Any("error", err),
				)
				return fmt.Errorf("could not register extra service: %w", err)
			}
		}
	}

	// Register mode-aware services
	if len(startConfig.modeAwareServices) > 0 {
		logger.Debug("registering mode-aware services")
		for _, modeService := range startConfig.modeAwareServices {
			// Check if any of the service's modes match the current configuration modes
			shouldRegister := false
			for _, serviceMode := range modeService.Modes {
				if slices.Contains(cfg.Mode, serviceMode) || serviceMode == "all" {
					shouldRegister = true
					break
				}
			}

			if shouldRegister {
				// Use the first matching mode for registration, or the service's namespace if no match
				registrationMode := modeService.Service.GetNamespace()
				for _, serviceMode := range modeService.Modes {
					if slices.Contains(cfg.Mode, serviceMode) {
						registrationMode = serviceMode
						break
					}
				}
				if slices.Contains(modeService.Modes, "all") {
					registrationMode = "all"
				}

				err := svcRegistry.RegisterService(modeService.Service, registrationMode)
				if err != nil {
					logger.Error("could not register mode-aware service",
						slog.String("namespace", modeService.Service.GetNamespace()),
						slog.Any("modes", modeService.Modes),
						slog.Any("error", err),
					)
					return fmt.Errorf("could not register mode-aware service: %w", err)
				}
				logger.Debug("registered mode-aware service",
					slog.String("namespace", modeService.Service.GetNamespace()),
					slog.String("service", modeService.Service.GetServiceDesc().ServiceName),
					slog.Any("supportedModes", modeService.Modes),
					slog.String("registeredWithMode", registrationMode),
				)
			} else {
				logger.Debug("skipping mode-aware service (no matching mode)",
					slog.String("namespace", modeService.Service.GetNamespace()),
					slog.String("service", modeService.Service.GetServiceDesc().ServiceName),
					slog.Any("supportedModes", modeService.Modes),
					slog.Any("configModes", cfg.Mode),
				)
			}
		}
	}

	logger.Info("registered the following core services", slog.Any("core_services", registeredCoreServices))

	var (
		sdkOptions []sdk.Option
		client     *sdk.SDK
		oidcconfig *auth.OIDCConfiguration
	)

	// If the mode is not all, does not include both core and entityresolution, or is not entityresolution on its own, we need to have a valid SDK config
	// entityresolution does not connect to other services and can run on its own
	// core only connects to entityresolution
	if !(slices.Contains(cfg.Mode, "all") || // no config required for all mode
		(slices.Contains(cfg.Mode, "core") && slices.Contains(cfg.Mode, "entityresolution")) || // or core and entityresolution modes togethor
		(slices.Contains(cfg.Mode, "entityresolution") && len(cfg.Mode) == 1)) && // or entityresolution on its own
		cfg.SDKConfig == (config.SDKConfig{}) {
		logger.Error("mode is not all, entityresolution, or a combination of core and entityresolution, but no sdk config provided")
		return errors.New("mode is not all, entityresolution, or a combination of core and entityresolution, but no sdk config provided")
	}

	// If client credentials are provided, use them
	if cfg.SDKConfig.ClientID != "" && cfg.SDKConfig.ClientSecret != "" {
		sdkOptions = append(sdkOptions, sdk.WithClientCredentials(cfg.SDKConfig.ClientID, cfg.SDKConfig.ClientSecret, nil))

		oidcconfig, err = auth.DiscoverOIDCConfiguration(ctx, cfg.Server.Auth.Issuer, logger)
		if err != nil {
			return fmt.Errorf("could not retrieve oidc configuration: %w", err)
		}

		// provide token endpoint -- sdk cannot discover it since well-known service isnt running yet
		sdkOptions = append(sdkOptions, sdk.WithTokenEndpoint(oidcconfig.TokenEndpoint))
	}

	// If the mode is all, use IPC for the SDK client
	if slices.Contains(cfg.Mode, "all") || //nolint:nestif // Need to handle all config options
		slices.Contains(cfg.Mode, "entityresolution") || // ERS does not connect to anything so it can also use IPC mode
		slices.Contains(cfg.Mode, "core") {
		// Use IPC for the SDK client
		sdkOptions = append(sdkOptions, sdk.WithIPC())
		sdkOptions = append(sdkOptions, sdk.WithCustomCoreConnection(otdf.ConnectRPCInProcess.Conn()))

		// handle ERS connection for core mode
		if slices.Contains(cfg.Mode, "core") && !slices.Contains(cfg.Mode, "entityresolution") {
			logger.Info("core mode")

			if cfg.SDKConfig.EntityResolutionConnection.Endpoint == "" {
				return errors.New("entityresolution endpoint must be provided in core mode")
			}

			ersConnectRPCConn := sdk.ConnectRPCConnection{}

			var tlsConfig *tls.Config
			if cfg.SDKConfig.EntityResolutionConnection.Insecure {
				tlsConfig = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true, // #nosec G402
				}
				ersConnectRPCConn.Client = httputil.SafeHTTPClientWithTLSConfig(tlsConfig)
			}
			if cfg.SDKConfig.EntityResolutionConnection.Plaintext {
				tlsConfig = &tls.Config{}
				ersConnectRPCConn.Client = httputil.SafeHTTPClient()
			}

			if cfg.SDKConfig.ClientID != "" && cfg.SDKConfig.ClientSecret != "" {
				if oidcconfig.Issuer == "" {
					// this should not occur, it will have been set above if this block is entered
					return errors.New("cannot add token interceptor: oidcconfig is empty")
				}

				rsaKeyPair, err := ocrypto.NewRSAKeyPair(dpopKeySize)
				if err != nil {
					return fmt.Errorf("could not generate RSA Key: %w", err)
				}
				ts, err := sdk.NewIDPAccessTokenSource(
					oauth.ClientCredentials{ClientID: cfg.SDKConfig.ClientID, ClientAuth: cfg.SDKConfig.ClientSecret},
					oidcconfig.TokenEndpoint,
					nil,
					&rsaKeyPair,
				)
				if err != nil {
					return fmt.Errorf("error creating ERS tokensource: %w", err)
				}

				interceptor := sdkauth.NewTokenAddingInterceptorWithClient(ts,
					httputil.SafeHTTPClientWithTLSConfig(tlsConfig))

				ersConnectRPCConn.Options = append(ersConnectRPCConn.Options, connect.WithInterceptors(interceptor.AddCredentialsConnect()))
			}

			if sdk.IsPlatformEndpointMalformed(cfg.SDKConfig.EntityResolutionConnection.Endpoint) {
				return fmt.Errorf("entityresolution endpoint is malformed: %s", cfg.SDKConfig.EntityResolutionConnection.Endpoint)
			}
			ersConnectRPCConn.Endpoint = cfg.SDKConfig.EntityResolutionConnection.Endpoint

			sdkOptions = append(sdkOptions, sdk.WithCustomEntityResolutionConnection(&ersConnectRPCConn))
			logger.Info("added with custom ers connection", slog.String("ers_connection_endpoint", ersConnectRPCConn.Endpoint))
		}

		client, err = sdk.New("", sdkOptions...)
		if err != nil {
			logger.Error("issue creating sdk client", slog.Any("error", err))
			return fmt.Errorf("issue creating sdk client: %w", err)
		}
	} else {
		// Use the provided SDK config
		if cfg.SDKConfig.CorePlatformConnection.Insecure {
			sdkOptions = append(sdkOptions, sdk.WithInsecureSkipVerifyConn())
		}
		if cfg.SDKConfig.CorePlatformConnection.Plaintext {
			sdkOptions = append(sdkOptions, sdk.WithInsecurePlaintextConn())
		}
		client, err = sdk.New(cfg.SDKConfig.CorePlatformConnection.Endpoint, sdkOptions...)
		if err != nil {
			logger.Error("issue creating sdk client", slog.String("error", err.Error()))
			return fmt.Errorf("issue creating sdk client: %w", err)
		}
	}

	defer client.Close()

	logger.Info("starting services")
	gatewayCleanup, err := startServices(ctx, startServicesParams{
		cfg:                 cfg,
		otdf:                otdf,
		client:              client,
		keyManagerFactories: startConfig.trustKeyManagers,
		logger:              logger,
		reg:                 svcRegistry,
		cacheManager:        cacheManager,
	})
	if err != nil {
		logger.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}
	defer gatewayCleanup()

	// Start watching the configuration for changes with registered config change service hooks
	if err := cfg.Watch(ctx); err != nil {
		return fmt.Errorf("failed to watch configuration: %w", err)
	}
	defer cfg.Close(ctx)

	// Start the server
	logger.Info("starting opentdf")
	if err := otdf.Start(); err != nil {
		return err
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
