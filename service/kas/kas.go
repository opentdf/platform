package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/go-viper/mapstructure/v2"
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
	return func(_ context.Context, cfg config.ServiceConfig) error {
		var kasCfg access.KASConfig
		if err := mapstructure.Decode(cfg, &kasCfg); err != nil {
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
				// Determine KAS URI based on public hostname and server's listening port/scheme
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
						panic(fmt.Errorf("could not extract port from KAS server address '%s': %w", serverAddr, err))
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

				kasURI, err := url.Parse(kasURLString)
				if err != nil {
					panic(fmt.Errorf("invalid kas address [%s] %w", kasURLString, err))
				}

				var kasCfg access.KASConfig
				if err := mapstructure.Decode(srp.Config, &kasCfg); err != nil {
					panic(fmt.Errorf("invalid kas cfg [%v] %w", srp.Config, err))
				} // kasURLString will be used for p.URI

				var cacheClient *cache.Cache
				if kasCfg.KeyCacheExpiration != 0 {
					cacheClient, err = srp.NewCacheClient(cache.Options{
						Expiration: kasCfg.KeyCacheExpiration,
					})
					if err != nil {
						panic(err)
					}
				}

				if kasCfg.Preview.KeyManagement {
					srp.Logger.Info("preview feature: key management is enabled")

					// Configure new delegation service
					p.KeyDelegator = trust.NewDelegatingKeyService(NewPlatformKeyIndexer(srp.SDK, kasURLString, srp.Logger), srp.Logger, cacheClient)
					for _, manager := range srp.KeyManagerFactories {
						p.KeyDelegator.RegisterKeyManager(manager.Name, manager.Factory)
					}

					// Register Basic Key Manager

					p.KeyDelegator.RegisterKeyManager(security.BasicManagerName, func(opts *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
						bm, err := security.NewBasicManager(opts.Logger, opts.Cache, kasCfg.RootKey)
						if err != nil {
							return nil, err
						}
						return bm, nil
					})
					// Explicitly set the default manager for session key generation.
					// This should be configurable, e.g., defaulting to BasicManager or an HSM if available.
					p.KeyDelegator.SetDefaultMode(security.BasicManagerName) // Example: default to BasicManager
				} else {
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
				}

				p.URI = *kasURI
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
