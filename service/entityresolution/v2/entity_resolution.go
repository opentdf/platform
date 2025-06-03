package entityresolution

import (
	"fmt"
	"log/slog"

	"github.com/creasty/defaults"
	"github.com/go-viper/mapstructure/v2"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution/v2/entityresolutionv2connect"
	"github.com/opentdf/platform/service/entityresolution/cache"
	claims "github.com/opentdf/platform/service/entityresolution/claims/v2"
	configV2 "github.com/opentdf/platform/service/entityresolution/config/v2"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak/v2"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

const (
	KeycloakMode = "keycloak"
	ClaimsMode   = "claims"
)

type EntityResolution struct {
	entityresolutionv2connect.EntityResolutionServiceHandler
	trace.Tracer
}

func NewRegistration() *serviceregistry.Service[entityresolutionv2connect.EntityResolutionServiceHandler] {
	return &serviceregistry.Service[entityresolutionv2connect.EntityResolutionServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[entityresolutionv2connect.EntityResolutionServiceHandler]{
			Namespace:      "entityresolution",
			Version:        "v2",
			ServiceDesc:    &ersV2.EntityResolutionService_ServiceDesc,
			ConnectRPCFunc: entityresolutionv2connect.NewEntityResolutionServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (entityresolutionv2connect.EntityResolutionServiceHandler, serviceregistry.HandlerServer) {
				cfg := new(configV2.ERSConfig)
				var (
					err error
					c   *cache.ResponseCache
				)

				if err := defaults.Set(cfg); err != nil {
					panic(fmt.Errorf("failed to set default values for ERS config: %w", err))
				}

				if srp.Config != nil {
					if err := mapstructure.Decode(srp.Config, &cfg); err != nil {
						panic(err)
					}
				}
				l := srp.Logger

				if cfg.CacheResponseLifetimeSeconds > 0 {
					c, err = cache.NewResponseCache(l, cfg)
					if err != nil {
						l.Error("failed to create response cache", slog.Any("error", err))
						panic(fmt.Errorf("failed to create response cache: %w", err))
					}
					l.Info("Response cache initialized", slog.Int("lifetime_seconds", cfg.CacheResponseLifetimeSeconds))
				}

				if cfg.Mode == ClaimsMode {
					claimsSVC, claimsHandler := claims.RegisterClaimsERS(srp.Config, l, c)
					claimsSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: claimsSVC}, claimsHandler
				}

				// Default to keycloak ERS
				kcSVC, kcHandler := keycloak.RegisterKeycloakERS(srp.Config, l, c)
				kcSVC.Tracer = srp.Tracer

				return EntityResolution{EntityResolutionServiceHandler: kcSVC, Tracer: srp.Tracer}, kcHandler
			},
		},
	}
}
