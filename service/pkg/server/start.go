package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/auth/oauth"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/tracing"
	wellknown "github.com/opentdf/platform/service/wellknownconfiguration"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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

	if cfg.Trace.Enabled {
		// Initialize tracer
		logger.Debug("configuring otel tracer")
		shutdown := tracing.InitTracer(cfg.Trace)
		defer shutdown()
	}

	logger.Info("starting opentdf services")

	// Set allowed public routes when platform is being extended
	if len(startConfig.PublicRoutes) > 0 {
		logger.Info("additional public routes added", slog.Any("routes", startConfig.PublicRoutes))
		cfg.Server.Auth.PublicRoutes = startConfig.PublicRoutes
	}

	// Set Default Policy
	if startConfig.bultinPolicyOverride != "" {
		cfg.Server.Auth.Policy.Builtin = startConfig.bultinPolicyOverride
	}

	// Set Casbin Adapter
	if startConfig.casbinAdapter != nil {
		cfg.Server.Auth.Policy.Adapter = startConfig.casbinAdapter
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
			err := svcRegistry.RegisterService(service, service.GetNamespace())
			if err != nil {
				logger.Error("could not register extra service", slog.String("namespace", service.GetNamespace()), slog.String("error", err.Error()))
				return fmt.Errorf("could not register extra service: %w", err)
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

			ersDialOptions := []grpc.DialOption{}
			var tlsConfig *tls.Config
			if cfg.SDKConfig.EntityResolutionConnection.Insecure {
				tlsConfig = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true, // #nosec G402
				}
				ersDialOptions = append(ersDialOptions, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			}
			if cfg.SDKConfig.EntityResolutionConnection.Plaintext {
				tlsConfig = &tls.Config{}
				ersDialOptions = append(ersDialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

				interceptor := sdkauth.NewTokenAddingInterceptor(ts, tlsConfig)

				ersDialOptions = append(ersDialOptions, grpc.WithChainUnaryInterceptor(interceptor.AddCredentials))
			}

			parsedURL, err := url.Parse(cfg.SDKConfig.EntityResolutionConnection.Endpoint)
			if err != nil {
				return fmt.Errorf("cannot parse ers url(%s): %w", cfg.SDKConfig.EntityResolutionConnection.Endpoint, err)
			}
			// Needed to support buffconn for testing
			if parsedURL.Host == "" {
				return errors.New("ERS host is empty when parsing")
			}
			port := parsedURL.Port()
			// if port is empty, default to 443.
			if port == "" {
				port = "443"
			}
			ersGRPCEndpoint := net.JoinHostPort(parsedURL.Hostname(), port)

			conn, err := grpc.NewClient(ersGRPCEndpoint, ersDialOptions...)
			if err != nil {
				return fmt.Errorf("could not connect to ERS: %w", err)
			}
			sdkOptions = append(sdkOptions, sdk.WithCustomEntityResolutionConnection(conn))
			logger.Info("added with custom ers connection for ", "", ersGRPCEndpoint)
		}

		client, err = sdk.New("", sdkOptions...)
		if err != nil {
			logger.Error("issue creating sdk client", slog.String("error", err.Error()))
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
	err = startServices(ctx, *cfg, otdf, client, logger, svcRegistry)
	if err != nil {
		logger.Error("issue starting services", slog.String("error", err.Error()))
		return fmt.Errorf("issue starting services: %w", err)
	}

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
