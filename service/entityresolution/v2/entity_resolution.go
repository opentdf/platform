package entityresolution

import (
	"log"
	"log/slog"
	"time"

	"github.com/go-viper/mapstructure/v2"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution/v2/entityresolutionv2connect"
	claims "github.com/opentdf/platform/service/entityresolution/claims/v2"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak/v2"
	multistrategyv2 "github.com/opentdf/platform/service/entityresolution/multi-strategy/v2"
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
	MultiStrategyMode = "multi-strategy"
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
					srp.Logger.Error("failed to decode entity resolution configuration", slog.Any("error", err))
					log.Fatalf("Failed to decode entity resolution configuration: %v", err)
				}

				// Set up cache if configured
				var ersCache *cache.Cache
				// default to no cache if no expiration is set
				if inputConfig.CacheExpiration != "" {
					exp, err := time.ParseDuration(inputConfig.CacheExpiration)
					if err != nil {
						srp.Logger.Error("failed to parse cache expiration duration", slog.Any("error", err))
						log.Fatalf("Invalid cache expiration duration '%s': %v", inputConfig.CacheExpiration, err)
					}
					ersCache, err = srp.NewCacheClient(cache.Options{
						Expiration: exp,
					})
					if err != nil {
						srp.Logger.Error("failed to create cache for Entity Resolution Service", slog.Any("error", err))
						log.Fatalf("Failed to create cache client for Entity Resolution Service: %v", err)
					}
				}

				switch inputConfig.Mode {
				case ClaimsMode:
					claimsSVC, claimsHandler := claims.RegisterClaimsERS(srp.Config, srp.Logger)
					claimsSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: claimsSVC}, claimsHandler
				case MultiStrategyMode:
					multiSVC, multiHandler := multistrategyv2.RegisterERSV2(srp.Config, srp.Logger)
					multiSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: multiSVC}, multiHandler
				default:
					// Default to Keycloak ERS with cache support
					kcSVC, kcHandler := keycloak.RegisterKeycloakERS(srp.Config, srp.Logger, ersCache)
					kcSVC.Tracer = srp.Tracer
					return EntityResolution{EntityResolutionServiceHandler: kcSVC, Tracer: srp.Tracer}, kcHandler
				}
			},
		},
	}
}
