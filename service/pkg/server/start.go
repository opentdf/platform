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
	loaderOrder := []string{
		config.LoaderNameEnvironmentValue,
		config.LoaderNameFile,
		config.LoaderNameDefaultSettings,
	}
	if startConfig.configLoaderOrder != nil {
		loaderOrder = startConfig.configLoaderOrder
	} else if startConfig.configLoaders != nil {
		for _, loader := range startConfig.configLoaders {
			loaderOrder = append(loaderOrder, loader.Name())
		}
	}

	additionalLoaderMap := make(map[string]config.Loader, len(startConfig.configLoaders))
	for _, loader := range startConfig.configLoaders {
		additionalLoaderMap[loader.Name()] = loader
	}

	loaders := make([]config.Loader, len(loaderOrder))

	for idx, loaderName := range loaderOrder {
		var loader config.Loader
		var err error
		switch loaderName {
		case config.LoaderNameEnvironmentValue:
			loader, err = config.NewEnvironmentValueLoader(startConfig.ConfigKey, nil)
			if err != nil {
				return err
			}
		case config.LoaderNameFile:
			loader, err = config.NewConfigFileLoader(startConfig.ConfigKey, startConfig.ConfigFile)
			if err != nil {
				return err
			}
		case config.LoaderNameDefaultSettings:
			loader, err = config.NewDefaultSettingsLoader()
			if err != nil {
				return err
			}
		default:
			mappedLoader, ok := additionalLoaderMap[loaderName]
			if !ok {
				return fmt.Errorf("loader not found: %s", loaderName)
			}
			loader = mappedLoader
		}
		loaders[idx] = loader
	}
	cfg, err := config.Load(ctx, loaders...)
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
	if err := RegisterEssentialServices(svcRegistry); err != nil {
		logger.Error("could not register essential services", slog.String("error", err.Error()))
		return fmt.Errorf("could not register essential services: %w", err)
	}

	logger.Debug("registering services")

	var registeredServices []string
	registeredServices, err = svcRegistry.RegisterServicesFromConfiguration(cfg.Mode, getServiceConfigurations())
	if err != nil {
		logger.Error("could not register core services", slog.String("error", err.Error()))
		return fmt.Errorf("could not register core services: %w", err)
	}

	// Register Extra Core Services
	if len(startConfig.extraCoreServices) > 0 {
		logger.Debug("registering extra core services")
		for _, service := range startConfig.extraCoreServices {
			err := svcRegistry.RegisterService(service, serviceregistry.ModeCore)
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
			err := svcRegistry.RegisterService(service, serviceregistry.ModeName(service.GetNamespace()))
			if err != nil {
				logger.Error("could not register extra service",
					slog.String("namespace", service.GetNamespace()),
					slog.Any("error", err),
				)
				return fmt.Errorf("could not register extra service: %w", err)
			}
		}
	}

	logger.Info("registered the following services", slog.Any("services", registeredServices))

	var (
		sdkOptions []sdk.Option
		client     *sdk.SDK
		oidcconfig *auth.OIDCConfiguration
	)

	// Check if SDK config is required for the current mode combination
	if modeRequiresSdkConfig(cfg) && cfg.SDKConfig == (config.SDKConfig{}) {
		logger.Error("no sdk config provided")
		return errors.New("no sdk config provided")
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

	// Configure SDK based on mode
	if modeRequiresIpc(cfg) {
		client, err = setupIPCSDK(cfg, oidcconfig, otdf, logger, sdkOptions)
	} else {
		client, err = setupExternalSDK(cfg, logger, sdkOptions)
	}
	if err != nil {
		return err
	}

	defer client.Close()

	logger.Info("starting services")
	gatewayCleanup, err := startServices(ctx, startServicesParams{
		cfg:                    cfg,
		otdf:                   otdf,
		client:                 client,
		keyManagerCtxFactories: startConfig.trustKeyManagerCtxs,
		logger:                 logger,
		reg:                    svcRegistry,
		cacheManager:           cacheManager,
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

func modeRequiresSdkConfig(cfg *config.Config) bool {
	// No SDK config required for 'all' mode
	if slices.Contains(cfg.Mode, serviceregistry.ModeALL.String()) {
		return false
	}

	// No SDK config required for entityresolution-only mode (runs standalone)
	if slices.Contains(cfg.Mode, serviceregistry.ModeERS.String()) && len(cfg.Mode) == 1 {
		return false
	}

	// No SDK config required when both core and entityresolution modes are present
	if slices.Contains(cfg.Mode, serviceregistry.ModeCore.String()) && slices.Contains(cfg.Mode, serviceregistry.ModeERS.String()) {
		return false
	}

	// All other mode combinations require SDK config
	return true
}

func modeRequiresIpc(cfg *config.Config) bool {
	// Use IPC for 'all' mode (everything runs in process)
	if slices.Contains(cfg.Mode, serviceregistry.ModeALL.String()) {
		return true
	}

	// Use IPC for entityresolution mode (does not connect to external services)
	if slices.Contains(cfg.Mode, serviceregistry.ModeERS.String()) {
		return true
	}

	// Use IPC for core mode (can use in-process connections)
	if slices.Contains(cfg.Mode, serviceregistry.ModeCore.String()) {
		return true
	}

	// All other modes use external SDK connections
	return false
}

// setupERSConnection creates an ERS connection configuration for core mode
func setupERSConnection(cfg *config.Config, oidcconfig *auth.OIDCConfiguration, logger *logger.Logger) (*sdk.ConnectRPCConnection, error) {
	if cfg.SDKConfig.EntityResolutionConnection.Endpoint == "" {
		return nil, errors.New("entityresolution endpoint must be provided in core mode")
	}

	ersConnectRPCConn := &sdk.ConnectRPCConnection{}

	// Configure TLS
	tlsConfig := configureTLSForERS(cfg, ersConnectRPCConn)

	// Configure authentication if credentials are provided
	if cfg.SDKConfig.ClientID != "" && cfg.SDKConfig.ClientSecret != "" {
		if err := configureERSAuthentication(logger, cfg, oidcconfig, tlsConfig, ersConnectRPCConn); err != nil {
			return nil, err
		}
	}

	// Validate and set endpoint
	if sdk.IsPlatformEndpointMalformed(cfg.SDKConfig.EntityResolutionConnection.Endpoint) {
		return nil, fmt.Errorf("entityresolution endpoint is malformed: %s", cfg.SDKConfig.EntityResolutionConnection.Endpoint)
	}
	ersConnectRPCConn.Endpoint = cfg.SDKConfig.EntityResolutionConnection.Endpoint

	logger.Info("added with custom ers connection", slog.String("ers_connection_endpoint", ersConnectRPCConn.Endpoint))
	return ersConnectRPCConn, nil
}

// configureTLSForERS configures TLS settings for ERS connection
func configureTLSForERS(cfg *config.Config, ersConnectRPCConn *sdk.ConnectRPCConnection) *tls.Config {
	var tlsConfig *tls.Config
	ersConn := &cfg.SDKConfig.EntityResolutionConnection

	if ersConn.Insecure {
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402
		}
		ersConnectRPCConn.Client = httputil.SafeHTTPClientWithTLSConfig(tlsConfig)
	} else if ersConn.Plaintext {
		tlsConfig = &tls.Config{}
		ersConnectRPCConn.Client = httputil.SafeHTTPClient()
	}

	return tlsConfig
}

// configureERSAuthentication sets up authentication for ERS connection
func configureERSAuthentication(logger *logger.Logger, cfg *config.Config, oidcconfig *auth.OIDCConfiguration, tlsConfig *tls.Config, ersConn *sdk.ConnectRPCConnection) error {
	if oidcconfig.Issuer == "" {
		return errors.New("cannot add token interceptor: oidcconfig is empty")
	}

	rsaKeyPair, err := ocrypto.NewRSAKeyPair(dpopKeySize)
	if err != nil {
		return fmt.Errorf("could not generate RSA Key: %w", err)
	}

	ts, err := sdk.NewIDPAccessTokenSource(
		logger.Logger,
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

	ersConn.Options = append(ersConn.Options, connect.WithInterceptors(interceptor.AddCredentialsConnect()))
	return nil
}

// setupIPCSDK configures and creates SDK client for IPC mode
func setupIPCSDK(cfg *config.Config, oidcconfig *auth.OIDCConfiguration, otdf *server.OpenTDFServer, logger *logger.Logger, sdkOptions []sdk.Option) (*sdk.SDK, error) {
	// Use IPC for the SDK client
	sdkOptions = append(sdkOptions, sdk.WithIPC())
	sdkOptions = append(sdkOptions, sdk.WithCustomCoreConnection(otdf.ConnectRPCInProcess.Conn()))

	// handle ERS connection for core mode
	if slices.Contains(cfg.Mode, serviceregistry.ModeCore.String()) && !slices.Contains(cfg.Mode, serviceregistry.ModeERS.String()) {
		logger.Info("core mode")

		ersConnectRPCConn, err := setupERSConnection(cfg, oidcconfig, logger)
		if err != nil {
			return nil, err
		}

		sdkOptions = append(sdkOptions, sdk.WithCustomEntityResolutionConnection(ersConnectRPCConn))
	}

	client, err := sdk.New("", sdkOptions...)
	if err != nil {
		logger.Error("issue creating sdk client", slog.Any("error", err))
		return nil, fmt.Errorf("issue creating sdk client: %w", err)
	}

	return client, nil
}

// setupExternalSDK configures and creates SDK client for external mode
func setupExternalSDK(cfg *config.Config, logger *logger.Logger, sdkOptions []sdk.Option) (*sdk.SDK, error) {
	// Use the provided SDK config
	if cfg.SDKConfig.CorePlatformConnection.Insecure {
		sdkOptions = append(sdkOptions, sdk.WithInsecureSkipVerifyConn())
	}
	if cfg.SDKConfig.CorePlatformConnection.Plaintext {
		sdkOptions = append(sdkOptions, sdk.WithInsecurePlaintextConn())
	}
	client, err := sdk.New(cfg.SDKConfig.CorePlatformConnection.Endpoint, sdkOptions...)
	if err != nil {
		logger.Error("issue creating sdk client", slog.String("error", err.Error()))
		return nil, fmt.Errorf("issue creating sdk client: %w", err)
	}
	return client, nil
}
