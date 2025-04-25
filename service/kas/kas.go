package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
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
				// FIXME msg="mismatched key access url" keyAccessURL=http://localhost:9000 kasURL=https://:9000
				hostWithPort := srp.OTDF.HTTPServer.Addr
				if strings.HasPrefix(hostWithPort, ":") {
					hostWithPort = "localhost" + hostWithPort
				}
				kasURLString := "http://" + hostWithPort
				kasURI, err := url.Parse(kasURLString)
				if err != nil {
					panic(fmt.Errorf("invalid kas address [%s] %w", kasURLString, err))
				}

				var kasCfg access.KASConfig
				if err := mapstructure.Decode(srp.Config, &kasCfg); err != nil {
					panic(fmt.Errorf("invalid kas cfg [%v] %w", srp.Config, err))
				}

				// Set up both the legacy CryptoProvider and the new SecurityProvider
				spa := security.NewSecurityProviderAdapter(srp.OTDF.CryptoProvider)
				p.KeyIndex = spa
				p.KeyManager = spa
				kasCfg.UpgradeMapToKeyring(srp.OTDF.CryptoProvider)

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
