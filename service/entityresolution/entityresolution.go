//nolint:sloglint // v1 entityresolution will be deprecated soon
package entityresolution

import (
	"log"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"
	claims "github.com/opentdf/platform/service/entityresolution/claims"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	multistrategy "github.com/opentdf/platform/service/entityresolution/multi-strategy"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

type ERSConfig struct {
	Mode            string `mapstructure:"mode" json:"mode"`
	CacheExpiration string `mapstructure:"cache_expiration" json:"cache_expiration"`
}

const (
	KeycloakMode      = "keycloak"
	ClaimsMode        = "claims"
	LDAPMode          = "ldap"
	SQLMode           = "sql"
	MultiStrategyMode = "multi-strategy"
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
					srp.Logger.Error("Failed to decode entity resolution configuration", "error", err)
					log.Fatalf("Failed to decode entity resolution configuration: %v", err)
				}

				// Set up cache if configured
				var ersCache *cache.Cache
				// default to no cache if no expiration is set
				if inputConfig.CacheExpiration != "" {
					exp, err := time.ParseDuration(inputConfig.CacheExpiration)
					if err != nil {
						srp.Logger.Error("Failed to parse cache expiration duration", "error", err)
						log.Fatalf("Invalid cache expiration duration '%s': %v", inputConfig.CacheExpiration, err)
					}
					ersCache, err = srp.NewCacheClient(cache.Options{
						Expiration: exp,
					})
					if err != nil {
						srp.Logger.Error("Failed to create cache for Entity Resolution Service", "error", err)
						log.Fatalf("Failed to create cache client for Entity Resolution Service: %v", err)
					}
				}

				switch inputConfig.Mode {
				case ClaimsMode:
					claimsSVC, claimsHandler := claims.RegisterClaimsERS(srp.Config, srp.Logger)
					claimsSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: claimsSVC}, claimsHandler
				case LDAPMode:
					srp.Logger.Error("LDAP mode is no longer supported. Please use multi-strategy mode instead.")
					log.Fatalf("LDAP mode has been removed. Please use multi-strategy mode with LDAP provider configuration.")
					panic("unreachable")
				case SQLMode:
					srp.Logger.Error("SQL mode is no longer supported. Please use multi-strategy mode instead.")
					log.Fatalf("SQL mode has been removed. Please use multi-strategy mode with SQL provider configuration.")
					panic("unreachable")
				case MultiStrategyMode:
					multiSVC, multiHandler := multistrategy.RegisterMultiStrategyERS(srp.Config, srp.Logger)
					multiSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: multiSVC}, multiHandler
				default:
					// Default to keycloak ERS with cache support
					kcSVC, kcHandler := keycloak.RegisterKeycloakERS(srp.Config, srp.Logger, ersCache)
					kcSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: kcSVC, Tracer: srp.Tracer}, kcHandler
				}
			},
		},
	}
}
