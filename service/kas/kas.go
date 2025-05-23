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

				if kasCfg.PreviewFeatures.KeyManagement {
					srp.Logger.Info("Key management is enabled")
					// Configure new delegation service
					p.KeyDelegator = trust.NewDelegatingKeyService(NewPlatformKeyIndexer(srp.SDK, kasURLString, srp.Logger))
					for _, manager := range srp.KeyManagers {
						p.KeyDelegator.RegisterKeyManager(manager.Name(), func() (trust.KeyManager, error) {
							return manager, nil
						})
					}

					// Register Basic Key Manager
					bm := security.NewBasicManager(srp.Logger.With("service", "basic-key-manager"), kasCfg.RootKey)
					p.KeyDelegator.RegisterKeyManager(bm.Name(), func() (trust.KeyManager, error) {
						return bm, nil
					})
				} else {
					// Set up both the legacy CryptoProvider and the new SecurityProvider
					kasCfg.UpgradeMapToKeyring(srp.OTDF.CryptoProvider)
					p.CryptoProvider = srp.OTDF.CryptoProvider

					inProcessService := p.InitSecurityProviderAdapter()

					p.KeyDelegator = trust.NewDelegatingKeyService(inProcessService)
					p.KeyDelegator.RegisterKeyManager(inProcessService.Name(), func() (trust.KeyManager, error) {
						return inProcessService, nil
					})
				}

				p.URI = *kasURI
				p.SDK = srp.SDK
				p.Logger = srp.Logger
				p.KASConfig = kasCfg
				p.Tracer = srp.Tracer

				srp.Logger.Debug("kas config", "config", kasCfg)

				if err := srp.RegisterReadinessCheck("kas", p.IsReady); err != nil {
					srp.Logger.Error("failed to register kas readiness check", slog.String("error", err.Error()))
				}

				return p, nil
			},
		},
	}
}
