//nolint:sloglint // v1 entityresolution will be deprecated soon
package entityresolution

import (
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"
	claims "github.com/opentdf/platform/service/entityresolution/claims"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
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
	entityresolutionconnect.EntityResolutionServiceHandler
	trace.Tracer
}

func NewRegistration() *serviceregistry.Service[entityresolutionconnect.EntityResolutionServiceHandler] {
	return &serviceregistry.Service[entityresolutionconnect.EntityResolutionServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[entityresolutionconnect.EntityResolutionServiceHandler]{
			Namespace:       "entityresolution",
			ServiceDesc:     &entityresolution.EntityResolutionService_ServiceDesc,
			ConnectRPCFunc:  entityresolutionconnect.NewEntityResolutionServiceHandler,
			GRPCGatewayFunc: entityresolution.RegisterEntityResolutionServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (entityresolutionconnect.EntityResolutionServiceHandler, serviceregistry.HandlerServer) {
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
						srp.Logger.Error("Failed to parse cache expiration duration", "error", err)
						panic(err)
					}
					ersCache, err = srp.NewCacheClient(cache.Options{
						Expiration: exp,
					})
					if err != nil {
						srp.Logger.Error("Failed to create cache for Entity Resolution Service", "error", err)
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
