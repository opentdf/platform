package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/lib/ocrypto"
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
		if err := mapstructure.Decode(cfg, &kasCfg); err != nil {
			return fmt.Errorf("invalid kas cfg [%v] %w", cfg, err)
		}

		p.ApplyConfig(kasCfg, p.SecurityConfig())
		p.Logger.TraceContext(ctx, "kas config reloaded", slog.Any("config", p.KASConfig))
		logSupportedMechanisms(ctx, p.Logger, p.KeyDelegator, &p.KASConfig)

		return nil
	}
}

func NewRegistration() *serviceregistry.Service[kasconnect.AccessServiceHandler] {
	p := new(access.Provider)
	onConfigUpdate := OnConfigUpdate(p)
	return &serviceregistry.Service[kasconnect.AccessServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[kasconnect.AccessServiceHandler]{
			Namespace:      "kas",
			ServiceDesc:    &kaspb.AccessService_ServiceDesc,
			ConnectRPCFunc: kasconnect.NewAccessServiceHandler,
			OnConfigUpdate: onConfigUpdate,
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

				var kmgrs []string

				if kasCfg.Preview.KeyManagement {
					srp.Logger.Info("preview feature: key management is enabled")

					kasURL, err := determineKASURL(srp, kasCfg)
					if err != nil {
						panic(fmt.Errorf("failed to determine KAS URL: %w", err))
					}

					srp.Logger.Debug("determined KAS URL", slog.String("kas_url", kasURL.String()))

					// Configure new delegation service
					p.KeyDelegator = trust.NewDelegatingKeyService(NewPlatformKeyIndexer(srp.SDK, kasURL.String(), srp.Logger), srp.Logger, cacheClient)
					for _, manager := range srp.KeyManagerCtxFactories {
						p.KeyDelegator.RegisterKeyManagerCtxWithAlgorithms(manager.Name, manager.Factory, manager.SupportedAlgorithms)
						kmgrs = append(kmgrs, manager.Name)
					}

					// Register Basic Key Manager
					p.KeyDelegator.RegisterKeyManagerCtxWithAlgorithms(security.BasicManagerName, func(_ context.Context, opts *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
						bm, err := security.NewBasicManager(opts.Logger, opts.Cache, kasCfg.RootKey)
						if err != nil {
							return nil, err
						}
						return bm, nil
					}, security.BasicManagerSupportedAlgorithms)
					kmgrs = append(kmgrs, security.BasicManagerName)
					// Explicitly set the default manager for session key generation.
					// This should be configurable, e.g., defaulting to BasicManager or an HSM if available.
					p.KeyDelegator.SetDefaultMode(security.BasicManagerName, "", nil) // Example: default to BasicManager
				} else {
					// Set up both the legacy CryptoProvider and the new SecurityProvider
					kasCfg.UpgradeMapToKeyring(srp.OTDF.CryptoProvider)
					p.CryptoProvider = srp.OTDF.CryptoProvider //nolint:staticcheck // Legacy field retained during migration.

					inProcessService := initSecurityProviderAdapter(p.CryptoProvider, kasCfg, srp.Logger) //nolint:staticcheck // Legacy field retained during migration.

					p.KeyDelegator = trust.NewDelegatingKeyService(inProcessService, srp.Logger, nil)
					p.KeyDelegator.RegisterKeyManagerCtxWithAlgorithms(inProcessService.Name(), func(_ context.Context, _ *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
						return inProcessService, nil
					}, security.InProcessSupportedAlgorithms)
					// Set default for non-key-management mode
					p.KeyDelegator.SetDefaultMode(inProcessService.Name(), "", nil)
					kmgrs = append(kmgrs, inProcessService.Name())
				}
				srp.Logger.Info("kas registered trust.KeyManagers", slog.Any("key_managers", kmgrs))

				p.SDK = srp.SDK
				p.Logger = srp.Logger
				p.ApplyConfig(kasCfg, srp.Security)
				p.Tracer = srp.Tracer

				srp.Logger.Debug("kas config loaded", slog.Any("config", p.KASConfig))
				logSupportedMechanisms(context.Background(), srp.Logger, p.KeyDelegator, &p.KASConfig)

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

// logSupportedMechanisms emits a single INFO entry listing the cryptographic
// mechanisms this KAS instance is configured to serve. The mechanism set is
// sourced from the trust KeyManagers (what they could serve if a key were
// provisioned) and filtered by the same preview-feature gates rewrap.go
// enforces, so the log only advertises algorithms rewrap would actually accept.
func logSupportedMechanisms(ctx context.Context, l *logger.Logger, kd *trust.DelegatingKeyService, kasCfg *access.KASConfig) {
	if l == nil || kd == nil || kasCfg == nil {
		return
	}
	mechanisms := filterMechanismsByPreview(kd.SupportedAlgorithms(ctx), kasCfg)
	l.InfoContext(ctx, "kas trust mechanisms initialized", slog.Any("mechanisms", mechanisms))
}

// filterMechanismsByPreview drops algorithms whose corresponding rewrap path is
// disabled. Keep aligned with the gating in service/kas/access/rewrap.go for
// "ec-wrapped", "hybrid-wrapped", and "mlkem-wrapped" key access objects.
func filterMechanismsByPreview(algs []ocrypto.KeyType, kasCfg *access.KASConfig) []ocrypto.KeyType {
	ecEnabled := kasCfg.ECTDFEnabled || kasCfg.Preview.ECTDFEnabled

	out := make([]ocrypto.KeyType, 0, len(algs))
	for _, a := range algs {
		switch {
		case !ecEnabled && ocrypto.IsECKeyType(a):
			continue
		case !kasCfg.Preview.HybridTDFEnabled && (ocrypto.IsHybridKeyType(a) || ocrypto.IsMLKEMKeyType(a)):
			continue
		case !kasCfg.Preview.MLKEMTDFEnabled && ocrypto.IsMLKEMKeyType(a):
			continue
		}
		out = append(out, a)
	}
	return out
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
		for _, alg := range []string{security.AlgorithmECP256R1, security.AlgorithmRSA2048, security.AlgorithmHPQTXWing} {
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
