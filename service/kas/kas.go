package kas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/trust"
)

func OnConfigUpdate(p *access.Provider) serviceregistry.OnConfigUpdateHook {
	return func(ctx context.Context, cfg config.ServiceConfig) error {
		var kasCfg access.KASConfig
		if err := config.BindServiceConfig(ctx, cfg, &kasCfg); err != nil {
			return fmt.Errorf("invalid kas cfg [%v] %w", cfg, err)
		}

		p.KASConfig = kasCfg
		p.Logger.Info("kas config reloaded")

		return nil
	}
}

func NewRegistration() *serviceregistry.Service[kasconnect.AccessServiceHandler] {
	p := new(access.Provider)
	onConfigUpdate := OnConfigUpdate(p)
	return &serviceregistry.Service[kasconnect.AccessServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[kasconnect.AccessServiceHandler]{
			Namespace:       "kas",
			ServiceDesc:     &kaspb.AccessService_ServiceDesc,
			ConnectRPCFunc:  kasconnect.NewAccessServiceHandler,
			GRPCGatewayFunc: kaspb.RegisterAccessServiceHandler,
			OnConfigUpdate:  onConfigUpdate,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (kasconnect.AccessServiceHandler, serviceregistry.HandlerServer) {
				var kasCfg access.KASConfig
				if err := config.BindServiceConfig(context.Background(), srp.Config, &kasCfg); err != nil {
					panic(fmt.Errorf("invalid kas cfg [%v] %w", srp.Config, err))
				}
				var cacheClient *cache.Cache
				if kasCfg.KeyCacheExpiration != 0 {
					var err error
					cacheClient, err = srp.NewCacheClient(cache.Options{
						Expiration: kasCfg.KeyCacheExpiration,
					})
					if err != nil {
						panic(err)
					}
				}

				var kmgrNames []string

				if kasCfg.Preview.KeyManagement {
					if err := handleKeyManagement(srp, kasCfg, p, cacheClient); err != nil {
						panic(err)
					}
					// Track registered manager names for logging
					for _, manager := range srp.KeyManagerFactories {
						kmgrNames = append(kmgrNames, manager.Name)
					}
					kmgrNames = append(kmgrNames, security.BasicManagerName)
				} else {
					name, err := handleLegacyMode(srp, kasCfg, p)
					if err != nil {
						panic(err)
					}
					kmgrNames = append(kmgrNames, name)
				}
				srp.Logger.Info("kas registered trust.KeyManagers", slog.Any("key_managers", kmgrNames))

				p.SDK = srp.SDK
				p.Logger = srp.Logger
				p.KASConfig = kasCfg
				p.Tracer = srp.Tracer

				srp.Logger.Debug("kas config", slog.Any("config", kasCfg))

				if err := srp.RegisterReadinessCheck("kas", p.IsReady); err != nil {
					srp.Logger.Error("failed to register kas readiness check", slog.String("error", err.Error()))
				}

				return p, nil
			},
		},
	}
}

func determineKASURL(srp serviceregistry.RegistrationParams, kasCfg access.KASConfig) (*url.URL, error) {
	if kasCfg.RegisteredKASURI != "" {
		srp.Logger.Debug("using registered KAS URL", slog.String("kas_url", kasCfg.RegisteredKASURI))
		kasURL, err := url.Parse(kasCfg.RegisteredKASURI)
		if err != nil {
			return nil, fmt.Errorf("invalid kas address [%s] %w", kasCfg.RegisteredKASURI, err)
		}
		return kasURL, nil
	}

	srp.Logger.Debug("no registered KAS URL found, determining based on configuration")

	// Determine KAS URL based on public hostname and server's listening port/scheme
	kasHost := srp.OTDF.PublicHostname
	serverAddr := srp.OTDF.HTTPServer.Addr

	// Extract port from serverAddr
	// serverAddr is typically in "host:port" or ":port" format
	_, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		// If SplitHostPort fails, it might be because serverAddr is just ":port"
		if strings.HasPrefix(serverAddr, ":") {
			port = strings.TrimPrefix(serverAddr, ":")
		} else {
			// Or if serverAddr is invalid or unexpected format
			return nil, fmt.Errorf("could not extract port from KAS server address '%s': %w", serverAddr, err)
		}
	}

	if kasHost == "" {
		// Fallback if PublicHostname is not configured
		hostFromServerAddr, _, _ := net.SplitHostPort(serverAddr) // Error already handled for port
		if hostFromServerAddr != "" && hostFromServerAddr != "0.0.0.0" {
			kasHost = hostFromServerAddr
		} else {
			// Default to localhost if listening on all interfaces or host is not specified in Addr
			kasHost = "localhost"
		}
	}

	scheme := "http"
	if srp.OTDF.HTTPServer.TLSConfig != nil {
		scheme = "https"
	}

	kasURLString := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(kasHost, port))

	kasURL, err := url.Parse(kasURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid kas address [%s] %w", kasURLString, err)
	}

	return kasURL, nil
}

func handleKeyManagement(srp serviceregistry.RegistrationParams, kasCfg *access.KASConfig, p *access.Provider, cacheClient *cache.Cache) error {
	srp.Logger.Info("preview feature: key management is enabled")
	srp.Logger.Debug("kas preview settings", slog.Any("preview", kasCfg.Preview))

	kasURL, err := determineKASURL(srp, *kasCfg)
	if err != nil {
		return fmt.Errorf("failed to determine KAS URL: %w", err)
	}
	srp.Logger.Debug("determined KAS URL", slog.String("kas_url", kasURL.String()))

	// Configure new delegation service
	p.KeyDelegator = trust.NewDelegatingKeyService(NewPlatformKeyIndexer(srp.SDK, kasURL.String(), srp.Logger), srp.Logger, cacheClient)
	for _, manager := range srp.KeyManagerFactories {
		p.KeyDelegator.RegisterKeyManager(manager.Name, manager.Factory)
	}

	// Register Basic Key Manager
	p.KeyDelegator.RegisterKeyManager(security.BasicManagerName, func(opts *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
		// RootKey is required when key management is enabled.
		if kasCfg.RootKey.IsZero() {
			return nil, errors.New("root_key is required when preview.key_management is enabled; set OPENTDF_SERVICES_KAS_ROOT_KEY or services.kas.root_key")
		}
		rk, err := kasCfg.RootKey.Resolve(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve root_key: %w", err)
		}
		bm, err := security.NewBasicManager(opts.Logger, opts.Cache, rk)
		if err != nil {
			return nil, err
		}
		return bm, nil
	})
	// Explicitly set the default manager for session key generation.
	p.KeyDelegator.SetDefaultMode(security.BasicManagerName)
	return nil
}

func handleLegacyMode(srp serviceregistry.RegistrationParams, kasCfg access.KASConfig, p *access.Provider) (string, error) { //nolint:unparam // maintains a consistent signature with other handlers
	// Set up both the legacy CryptoProvider and the new SecurityProvider
	kasCfg.UpgradeMapToKeyring(srp.OTDF.CryptoProvider)
	p.CryptoProvider = srp.OTDF.CryptoProvider

	inProcessService := initSecurityProviderAdapter(p.CryptoProvider, kasCfg, srp.Logger)

	p.KeyDelegator = trust.NewDelegatingKeyService(inProcessService, srp.Logger, nil)
	p.KeyDelegator.RegisterKeyManager(inProcessService.Name(), func(*trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
		return inProcessService, nil
	})
	// Set default for non-key-management mode
	p.KeyDelegator.SetDefaultMode(inProcessService.Name())
	return inProcessService.Name(), nil
}

func initSecurityProviderAdapter(cryptoProvider *security.StandardCrypto, kasCfg access.KASConfig, l *logger.Logger) trust.KeyService {
	var defaults []string
	var legacies []string
	for _, key := range kasCfg.Keyring {
		if key.Legacy {
			legacies = append(legacies, key.KID)
		} else {
			defaults = append(defaults, key.KID)
		}
	}
	if len(defaults) == 0 && len(legacies) == 0 {
		for _, alg := range []string{security.AlgorithmECP256R1, security.AlgorithmRSA2048} {
			kid := cryptoProvider.FindKID(alg)
			if kid != "" {
				defaults = append(defaults, kid)
			} else {
				l.Warn("no default key found for algorithm", slog.String("algorithm", alg))
			}
		}
	}

	return security.NewSecurityProviderAdapter(cryptoProvider, defaults, legacies)
}
