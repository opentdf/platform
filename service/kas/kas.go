package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/mitchellh/mapstructure"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "kas",
		ServiceDesc: &kaspb.AccessService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
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
			if err := mapstructure.Decode(srp.Config.ExtraProps, &kasCfg); err != nil {
				panic(fmt.Errorf("invalid kas cfg [%v] %w", srp.Config.ExtraProps, err))
			}

			switch {
			case kasCfg.ECCertID != "" && len(kasCfg.Keyring) > 0:
				panic("invalid kas cfg: please specify keyring or eccertid, not both")
			case len(kasCfg.Keyring) == 0:
				deprecatedOrDefault := func(kid, alg string) {
					if kid == "" {
						kid = srp.OTDF.CryptoProvider.FindKID(alg)
					}
					if kid == "" {
						srp.Logger.Warn("no known key for alg", "algorithm", alg)
						return
					}
					kasCfg.Keyring = append(kasCfg.Keyring, access.CurrentKeyFor{
						Algorithm: alg,
						KID:       kid,
					})
					kasCfg.Keyring = append(kasCfg.Keyring, access.CurrentKeyFor{
						Algorithm: alg,
						KID:       kid,
						Legacy:    true,
					})
				}
				deprecatedOrDefault(kasCfg.ECCertID, security.AlgorithmECP256R1)
				deprecatedOrDefault(kasCfg.RSACertID, security.AlgorithmRSA2048)
			default:
				kasCfg.Keyring = append(kasCfg.Keyring, inferLegacyKeys(kasCfg.Keyring)...)
			}

			p := access.Provider{
				URI:            *kasURI,
				AttributeSvc:   nil,
				CryptoProvider: srp.OTDF.CryptoProvider,
				SDK:            srp.SDK,
				Logger:         srp.Logger,
				Config:         &srp.Config,
				KASConfig:      kasCfg,
			}

			if err := srp.RegisterReadinessCheck("kas", p.IsReady); err != nil {
				srp.Logger.Error("failed to register kas readiness check", slog.String("error", err.Error()))
			}

			return &p, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				kas, ok := server.(*access.Provider)
				if !ok {
					panic("invalid kas server object")
				}
				return kaspb.RegisterAccessServiceHandlerServer(ctx, mux, kas)
			}
		},
	}
}

// If there exists *any* legacy keys, returns empty list.
// Otherwise, create a copy with legacy=true for all values
func inferLegacyKeys(keys []access.CurrentKeyFor) []access.CurrentKeyFor {
	for _, k := range keys {
		if k.Legacy {
			return nil
		}
	}
	l := make([]access.CurrentKeyFor, len(keys))
	for i, k := range keys {
		l[i] = k
		l[i].Legacy = true
	}
	return l
}
