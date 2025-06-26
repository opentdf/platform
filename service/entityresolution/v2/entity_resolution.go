package entityresolution

import (
	"log/slog"
	"time"

	"github.com/go-viper/mapstructure/v2"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution/v2/entityresolutionv2connect"
	claims "github.com/opentdf/platform/service/entityresolution/claims/v2"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak/v2"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

type ERSConfig struct {
	Mode            string `mapstructure:"mode" json:"mode"`
	CacheExpiration string `mapstructure:"cache_expiration" json:"cache_expiration"`
}

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
				var inputConfig ERSConfig

				if err := mapstructure.Decode(srp.Config, &inputConfig); err != nil {
					panic(err)
				}
				if inputConfig.Mode == ClaimsMode {
					claimsSVC, claimsHandler := claims.RegisterClaimsERS(srp.Config, srp.Logger)
					claimsSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: claimsSVC}, claimsHandler
				}

				var ersCache *cache.Cache
				// default to no cache if no exipiration is set
				if inputConfig.CacheExpiration != "" {
					exp, err := time.ParseDuration(inputConfig.CacheExpiration)
					if err != nil {
						srp.Logger.Error("failed to parse cache expiration duration", slog.Any("error", err))
						panic(err)
					}
					ersCache, err = srp.NewCacheClient(cache.Options{
						Expiration: exp,
					})
					if err != nil {
						srp.Logger.Error("failed to create cache for Entity Resolution Service", slog.Any("error", err))
						panic(err)
					}
				}

				// Default to keycloak ERS
				kcSVC, kcHandler := keycloak.RegisterKeycloakERS(srp.Config, srp.Logger, ersCache)
				kcSVC.Tracer = srp.Tracer

				return EntityResolution{EntityResolutionServiceHandler: kcSVC, Tracer: srp.Tracer}, kcHandler
			},
		},
	}
}
