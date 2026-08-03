package multistrategy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
	multistrategy "github.com/opentdf/platform/service/entityresolution/multi-strategy"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/protohelper"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// ERSV2 implements the EntityResolutionServiceHandler for v2 multi-strategy resolution
type ERSV2 struct {
	ersV2.UnimplementedEntityResolutionServiceServer
	service *multistrategy.Service
	logger  *logger.Logger
	trace.Tracer
}

// NewERSV2 creates a new v2 multi-strategy ERS
func NewERSV2(ctx context.Context, config types.MultiStrategyConfig, logger *logger.Logger) (*ERSV2, error) {
	service, err := multistrategy.NewService(ctx, config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create multi-strategy service: %w", err)
	}

	return &ERSV2{
		service: service,
		logger:  logger,
	}, nil
}

// GetService returns the underlying multi-strategy service for testing and health checks
func (ers *ERSV2) GetService() *multistrategy.Service {
	return ers.service
}

// ResolveEntities implements the v2 EntityResolutionServiceHandler interface
func (ers *ERSV2) ResolveEntities(
	ctx context.Context,
	req *connect.Request[ersV2.ResolveEntitiesRequest],
) (*connect.Response[ersV2.ResolveEntitiesResponse], error) {
	payload := req.Msg.GetEntities()
	resolvedEntities := make([]*ersV2.EntityRepresentation, 0, len(payload))

	for idx, entityV2 := range payload {
		entityID := entityV2.GetEphemeralId()
		if entityID == "" {
			entityID = ent.EntityIDPrefix + strconv.Itoa(idx)
			ers.logger.Warn("empty entity ID in request; using generated ID", slog.String("entity_id", entityID))
		}

		resolveCtx := ctx
		var claimsMap types.JWTClaims
		switch entityV2.GetEntityType().(type) {
		case *entity.Entity_Claims:
			claims := entityV2.GetClaims()
			if claims != nil {
				// First unmarshal to structpb.Struct
				var claimsStruct structpb.Struct
				err := claims.UnmarshalTo(&claimsStruct)
				if err != nil {
					return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err))
				}
				// Convert to map[string]interface{}
				claimsMap = claimsStruct.AsMap()
				resolveCtx = context.WithValue(ctx, types.JWTClaimsContextKey, claimsMap)
			}
		default:
			entityBytes, err := protojson.Marshal(entityV2)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(entityBytes, &claimsMap)
			if err != nil {
				return nil, err
			}
		}

		// Resolve entity using multi-strategy service
		result, err := ers.service.ResolveEntity(resolveCtx, entityID, claimsMap)
		if err != nil {
			ers.logger.Error("failed to resolve entity",
				slog.String("entity_id", entityID),
				slog.String("error", err.Error()))

			// Create error struct
			errorStruct, structErr := structpb.NewStruct(map[string]interface{}{
				"error":     err.Error(),
				"entity_id": entityID,
			})
			if structErr != nil {
				ers.logger.Error("failed to create error struct", slog.String("error", structErr.Error()))
				continue
			}

			resolvedEntities = append(resolvedEntities, &ersV2.EntityRepresentation{
				OriginalId:      entityID,
				AdditionalProps: []*structpb.Struct{errorStruct},
			})
			continue
		}

		// Convert all resolved claims to protobuf-compatible JSON values at once.
		resultData, err := claimsToResultData(result.Claims)
		if err != nil {
			ers.logger.Error("failed to normalize resolved claims",
				slog.String("entity_id", entityID),
				slog.String("error", err.Error()))
			continue
		}

		// Add metadata with "metadata_" prefix
		for metaKey, metaValue := range result.Metadata {
			resultData[("metadata_" + metaKey)] = protohelper.StructPBCompatibleValue(metaValue)
		}

		// Convert to protobuf struct
		resultStruct, structErr := structpb.NewStruct(resultData)
		if structErr != nil {
			ers.logger.Error("failed to create result struct",
				slog.String("entity_id", entityID),
				slog.String("error", structErr.Error()))
			continue
		}

		resolvedEntities = append(resolvedEntities, &ersV2.EntityRepresentation{
			OriginalId:      entityID,
			AdditionalProps: []*structpb.Struct{resultStruct},
		})
	}

	return connect.NewResponse(&ersV2.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}), nil
}

// CreateEntityChainsFromTokens implements the v2 EntityResolutionServiceHandler interface
func (ers *ERSV2) CreateEntityChainsFromTokens(
	ctx context.Context,
	req *connect.Request[ersV2.CreateEntityChainsFromTokensRequest],
) (*connect.Response[ersV2.CreateEntityChainsFromTokensResponse], error) {
	entityChains := make([]*entity.EntityChain, 0, len(req.Msg.GetTokens()))

	// FAIL-SAFE: If ANY token fails to create a complete entity chain, fail the entire request
	// This ensures authorization decisions are made with complete identity context
	for _, token := range req.Msg.GetTokens() {
		entityChain, err := ers.createEntityChainFromSingleTokenV2(ctx, token)
		if err != nil {
			ers.logger.ErrorContext(ctx, "failed to create entity chain from token - FAILING REQUEST for security",
				slog.String("token_id", token.GetEphemeralId()),
				slog.String("error", err.Error()))
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("failed to create entity chain for token %s: %w", token.GetEphemeralId(), err))
		}

		// Validate that we have at least one entity in the chain
		if len(entityChain.GetEntities()) == 0 {
			ers.logger.ErrorContext(ctx, "entity chain is empty - FAILING REQUEST for security",
				slog.String("token_id", token.GetEphemeralId()))
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("entity chain for token %s is empty - incomplete identity context", token.GetEphemeralId()))
		}

		entityChains = append(entityChains, entityChain)
	}

	ers.logger.DebugContext(ctx, "successfully created entity chains",
		slog.Int("chain_count", len(entityChains)),
		slog.Int("total_entities", ers.countEntitiesInChainsV2(entityChains)))

	return connect.NewResponse(&ersV2.CreateEntityChainsFromTokensResponse{
		EntityChains: entityChains,
	}), nil
}

// createEntityChainFromSingleTokenV2 processes a single JWT token using multi-strategy resolution for v2
func (ers *ERSV2) createEntityChainFromSingleTokenV2(ctx context.Context, token *entity.Token) (*entity.EntityChain, error) {
	// Parse JWT to extract claims
	jwtClaims, err := ers.parseJWTClaims(ctx, token.GetJwt())
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeMapping,
			"failed to parse JWT token",
			err,
			map[string]interface{}{
				"token_id": token.GetEphemeralId(),
			},
		)
	}

	// Get matching strategies for these JWT claims
	strategies, err := ers.service.GetStrategyMatcher().SelectStrategies(ctx, jwtClaims)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeStrategy,
			"failed to select strategies for JWT claims",
			err,
			map[string]interface{}{
				"token_id":   token.GetEphemeralId(),
				"entity_map": extractClaimNames(jwtClaims),
			},
		)
	}

	if len(strategies) == 0 {
		return nil, types.NewConfigurationError(
			"no matching strategies found for JWT claims",
			map[string]interface{}{
				"token_id":   token.GetEphemeralId(),
				"entity_map": extractClaimNames(jwtClaims),
			},
		)
	}

	entities := make([]*entity.Entity, 0)
	var lastError error
	var attemptedStrategies []string

	// Try strategies based on service-level failure strategy configuration
	failureStrategy := ers.service.GetConfig().FailureStrategy
	if failureStrategy == "" {
		failureStrategy = types.FailureStrategyFailFast
	}

	for _, strategy := range strategies {
		attemptedStrategies = append(attemptedStrategies, strategy.Name)

		// Put JWT claims into context for providers to access
		ctxWithClaims := context.WithValue(ctx, types.JWTClaimsContextKey, jwtClaims)

		// Resolve entity using this already-selected strategy.
		entityResult, err := ers.service.ResolveEntityWithStrategy(ctxWithClaims, token.GetEphemeralId(), jwtClaims, strategy)
		if err != nil {
			lastError = err
			ers.logger.WarnContext(ctx, "strategy failed for token",
				slog.String("token_id", token.GetEphemeralId()),
				slog.String("strategy", strategy.Name),
				slog.String("error", err.Error()))

			// If fail-fast, return error immediately
			if failureStrategy == types.FailureStrategyFailFast {
				return nil, types.WrapMultiStrategyError(
					types.ErrorTypeStrategy,
					"strategy execution failed with fail-fast policy",
					err,
					map[string]interface{}{
						"token_id":             token.GetEphemeralId(),
						"strategy":             strategy.Name,
						"failure_strategy":     failureStrategy,
						"attempted_strategies": attemptedStrategies,
					},
				)
			}

			// Continue to next strategy
			continue
		}

		// Success! Create entity from result
		entityV2 := ers.createEntityFromResultV2(ctx, entityResult, strategy, token.GetEphemeralId())
		entities = append(entities, entityV2)

		ers.logger.DebugContext(ctx, "successfully resolved entity for token",
			slog.String("token_id", token.GetEphemeralId()),
			slog.String("strategy", strategy.Name),
			slog.String("entity_type", getEntityTypeStringV2(entityV2)),
			slog.String("entity_category", entityV2.GetCategory().String()))

		// ENHANCED: Continue trying additional strategies to build multi-entity chains (like Keycloak)
		// This allows creating chains with multiple entities (e.g., ENVIRONMENT + SUBJECT)
		// Only break if FailureStrategy is FailFast and we have at least one successful entity
		if failureStrategy == types.FailureStrategyFailFast {
			break
		}
		// With FailureStrategyContinue, we continue to try more strategies to build richer chains
	}

	// If no strategies succeeded
	if len(entities) == 0 {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeStrategy,
			"all strategies failed for token",
			lastError,
			map[string]interface{}{
				"token_id":             token.GetEphemeralId(),
				"failure_strategy":     failureStrategy,
				"attempted_strategies": attemptedStrategies,
				"entity_map":           extractClaimNames(jwtClaims),
			},
		)
	}

	return &entity.EntityChain{
		EphemeralId: token.GetEphemeralId(),
		Entities:    entities,
	}, nil
}

// createEntityFromResultV2 converts a multi-strategy EntityResult to a v2 entity.Entity.
//
// For token-derived entity chains, preserve the resolved claims directly in the chain so
// downstream authz can consume the resolved subject/environment context without rehydrating
// through ERS and re-routing strategy selection from a lossy identity projection.
//
// EntityResult.Metadata is intentionally omitted. It describes ERS resolution mechanics and
// provenance, not the subject or environment entity. Including it in this claims payload would
// expose it to subject mappings and couple portable ABAC policy to multi-strategy provider names,
// strategy ordering, and other deployment-specific ERS structure. Resolution metadata belongs
// in observability or a dedicated out-of-band metadata channel, not in policy input.
func (ers *ERSV2) createEntityFromResultV2(ctx context.Context, result *types.EntityResult, strategy *types.MappingStrategy, tokenID string) *entity.Entity {
	category := entity.Entity_CATEGORY_SUBJECT
	if strategy.EntityType == types.EntityTypeEnvironment {
		category = entity.Entity_CATEGORY_ENVIRONMENT
	}

	resultData, err := claimsToResultData(result.Claims)
	if err != nil {
		ers.logger.WarnContext(ctx, "failed to normalize resolved claims for entity chain, falling back to minimal claims payload",
			slog.String("token_id", tokenID),
			slog.String("strategy", strategy.Name),
			slog.String("error", err.Error()))
		resultData = map[string]interface{}{}
		for key, value := range result.Claims {
			resultData[key] = protohelper.StructPBCompatibleValue(value)
		}
	}

	claimsStruct, err := structpb.NewStruct(resultData)
	if err != nil {
		ers.logger.WarnContext(ctx, "failed to build structpb claims for entity chain, using fallback token id claim",
			slog.String("token_id", tokenID),
			slog.String("strategy", strategy.Name),
			slog.String("error", err.Error()))
		claimsStruct, _ = structpb.NewStruct(map[string]interface{}{"token_id": tokenID})
	}

	claimsAny, err := anypb.New(claimsStruct)
	if err != nil {
		ers.logger.WarnContext(ctx, "failed to wrap claims payload for entity chain, using fallback token id claim",
			slog.String("token_id", tokenID),
			slog.String("strategy", strategy.Name),
			slog.String("error", err.Error()))
		fallbackStruct, _ := structpb.NewStruct(map[string]interface{}{"token_id": tokenID})
		claimsAny, _ = anypb.New(fallbackStruct)
	}

	entityID := fmt.Sprintf("%s-%s-claims-%s",
		strategy.Name,
		tokenID,
		preferredEntityValueFromClaims(result.Claims, tokenID))

	return &entity.Entity{
		EphemeralId: entityID,
		EntityType:  &entity.Entity_Claims{Claims: claimsAny},
		Category:    category,
	}
}

func claimsToResultData(claims map[string]interface{}) (map[string]interface{}, error) {
	bytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	resultData := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &resultData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	if resultData == nil {
		resultData = make(map[string]interface{})
	}
	return resultData, nil
}

// Helper functions for v2
func (ers *ERSV2) parseJWTClaims(ctx context.Context, jwtString string) (types.JWTClaims, error) {
	// For now, use a simple JWT parser (in production, this should validate signatures)
	// This is similar to how Keycloak ERS parses JWTs
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, err := token.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	return types.JWTClaims(claims), nil
}

func (ers *ERSV2) countEntitiesInChainsV2(chains []*entity.EntityChain) int {
	total := 0
	for _, chain := range chains {
		total += len(chain.GetEntities())
	}
	return total
}

func getEntityTypeStringV2(entityV2 *entity.Entity) string {
	switch entityV2.GetEntityType().(type) {
	case *entity.Entity_UserName:
		return "username"
	case *entity.Entity_EmailAddress:
		return "email"
	case *entity.Entity_ClientId:
		return "client_id"
	case *entity.Entity_Claims:
		return "claims"
	default:
		return "unknown"
	}
}

func preferredEntityValueFromClaims(claims map[string]interface{}, fallback string) string {
	for _, key := range []string{"username", "email_address", "client_id", "subject"} {
		if raw, exists := claims[key]; exists {
			if value, ok := raw.(string); ok && value != "" {
				return value
			}
		}
	}
	return fallback
}

// RegisterMultiStrategyERSV2 registers the v2 multi-strategy ERS service
func RegisterMultiStrategyERSV2(config map[string]interface{}, logger *logger.Logger) (*ERSV2, serviceregistry.HandlerServer) {
	var multiStrategyConfig types.MultiStrategyConfig

	if err := mapstructure.Decode(config, &multiStrategyConfig); err != nil {
		logger.Error("failed to decode multi-strategy configuration", slog.Any("error", err))
		panic(fmt.Sprintf("Failed to decode multi-strategy configuration: %v", err))
	}

	ers, err := NewERSV2(context.Background(), multiStrategyConfig, logger)
	if err != nil {
		logger.Error("failed to create multi-strategy ERS v2", slog.Any("error", err))
		panic(fmt.Sprintf("Failed to create multi-strategy ERS v2: %v", err))
	}

	return ers, nil
}

// extractClaimNames extracts the names of fields from JWTClaims for logging
func extractClaimNames(claims types.JWTClaims) []string {
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	return names
}
