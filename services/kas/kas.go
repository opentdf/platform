package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/pkg/serviceregistry"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/services/kas/access"
)

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "kas",
		ServiceDesc: &kaspb.AccessService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			hsm := srp.OTDF.HSM
			if hsm == nil {
				slog.Error("hsm not enabled")
				panic(fmt.Errorf("hsm not enabled"))
			}
			kasURLString := "https://" + srp.OTDF.HTTPServer.Addr
			kasURI, err := url.Parse(kasURLString)
			if err != nil {
				panic(fmt.Errorf("invalid kas address [%s] %w", kasURLString, err))
			}

			p := access.Provider{
				URI:          *kasURI,
				AttributeSvc: nil,
				Session:      *hsm,
				OIDCVerifier: nil,
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
