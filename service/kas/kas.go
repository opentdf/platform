package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
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

			p := access.Provider{
				URI:            *kasURI,
				AttributeSvc:   nil,
				CryptoProvider: srp.OTDF.CryptoProvider,
				SDK:            srp.SDK,
				Logger:         srp.Logger,
			}

			if err := srp.RegisterReadinessCheck("kas", p.IsReady); err != nil {
				slog.Error("failed to register kas readiness check", slog.String("error", err.Error()))
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
