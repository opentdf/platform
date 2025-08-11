package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

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
				var kasCfg access.KASConfig
				if err := mapstructure.Decode(srp.Config, &kasCfg); err != nil {
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

				if kasCfg.Preview.KeyManagement.Enabled {
					srp.Logger.Info("preview feature: key management is enabled")

					if kasCfg.Preview.KeyManagement.RegisteredKASURI == "" {
						panic("registered KAS URI is required when key management is enabled")
					}
					kasURL, err := url.Parse(kasCfg.Preview.KeyManagement.RegisteredKASURI)
					if err != nil {
						panic(fmt.Errorf("failed to parse registered KAS URI [%v]: %w", kasCfg.Preview.KeyManagement.RegisteredKASURI, err))
					}

					srp.Logger.Info("using registered KAS URI", slog.String("uri", kasURL.String()))

					// Configure new delegation service
					p.KeyDelegator = trust.NewDelegatingKeyService(NewPlatformKeyIndexer(srp.SDK, kasURL.String(), srp.Logger), srp.Logger, cacheClient)
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
