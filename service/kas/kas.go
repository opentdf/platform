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
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

func NewRegistration() *serviceregistry.Service[kasconnect.AccessServiceHandler] {
	return &serviceregistry.Service[kasconnect.AccessServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[kasconnect.AccessServiceHandler]{
			Namespace:      "kas",
			ServiceDesc:    &kaspb.AccessService_ServiceDesc,
			ConnectRPCFunc: kasconnect.NewAccessServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (kasconnect.AccessServiceHandler, serviceregistry.HandlerServer) {
				// Existing logic for KAS setup
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
				kasCfg.UpgradeMapToKeyring(srp.OTDF.CryptoProvider)

				p := &access.Provider{
					URI:            *kasURI,
					AttributeSvc:   nil,
					CryptoProvider: srp.OTDF.CryptoProvider,
					SDK:            srp.SDK,
					Logger:         srp.Logger,
					KASConfig:      kasCfg,
					Tracer:         srp.Tracer,
				}

				srp.Logger.Debug("kas config", "config", kasCfg)

				if err := srp.RegisterReadinessCheck("kas", p.IsReady); err != nil {
					srp.Logger.Error("failed to register kas readiness check", slog.String("error", err.Error()))
				}

				// Register the KAS legacy REST handlers for backwards compatibility
				// These were previously handled by gRPC-gateway which is now deprecated
				// legacy support is required to ensure TDFs are still accessible
				handlerServer := func(ctx context.Context, mux *runtime.ServeMux) error {
					mux.HandlePath(access.LegacyPublicKey.Method, access.LegacyPublicKey.Path, p.LegacyMuxHandlerPublicKey)
					mux.HandlePath(access.LegacyPublicKeyV2.Method, access.LegacyPublicKeyV2.Path, p.LegacyMuxHandlerPublicKey)
					mux.HandlePath(access.LegacyRewrap.Method, access.LegacyRewrap.Path, p.LegacyMuxHandlerRewrap)
					return nil
				}

				return p, handlerServer
			},
		},
	}
}
