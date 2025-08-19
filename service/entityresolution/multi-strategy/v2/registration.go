package multistrategy

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	multistrategy "github.com/opentdf/platform/service/entityresolution/multi-strategy"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
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
	// Extract JWT claims from context (this would be set by authentication middleware)
	jwtClaims, ok := ctx.Value(types.JWTClaimsContextKey).(types.JWTClaims)
	if !ok {
		ers.logger.Warn("no JWT claims found in context for multi-strategy ERS v2")
		// For ResolveEntities, we need JWT claims to be provided by middleware
		// This is different from CreateEntityChainsFromTokens which has the JWT token directly
		jwtClaims = make(types.JWTClaims)
	}

	payload := req.Msg.GetEntities()
	resolvedEntities := make([]*ersV2.EntityRepresentation, 0, len(payload))

	for _, entityV2 := range payload {
		entityID := entityV2.GetEphemeralId()
		if entityID == "" {
			ers.logger.Warn("empty entity ID in request")
			continue
		}

		// Resolve entity using multi-strategy service
		result, err := ers.service.ResolveEntity(ctx, entityID, jwtClaims)
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

		// Convert multi-strategy result to v2 protocol format
		resultData := make(map[string]interface{})

		// Add resolved claims
		for claimName, claimValue := range result.Claims {
			resultData[claimName] = claimValue
		}

		// Add metadata with "metadata_" prefix
		for metaKey, metaValue := range result.Metadata {
			resultData[("metadata_" + metaKey)] = metaValue
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
				"jwt_claims": extractClaimNames(jwtClaims),
			},
		)
	}

	if len(strategies) == 0 {
		return nil, types.NewConfigurationError(
			"no matching strategies found for JWT claims",
			map[string]interface{}{
				"token_id":   token.GetEphemeralId(),
				"jwt_claims": extractClaimNames(jwtClaims),
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

		// Resolve entity using this strategy
		entityResult, err := ers.service.ResolveEntity(ctxWithClaims, token.GetEphemeralId(), jwtClaims)
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
				"jwt_claims":           extractClaimNames(jwtClaims),
			},
		)
	}

	return &entity.EntityChain{
		EphemeralId: token.GetEphemeralId(),
		Entities:    entities,
	}, nil
}

// createEntityFromResultV2 converts a multi-strategy EntityResult to a v2 entity.Entity
func (ers *ERSV2) createEntityFromResultV2(ctx context.Context, result *types.EntityResult, strategy *types.MappingStrategy, tokenID string) *entity.Entity {
	// Determine entity category based on strategy configuration
	category := entity.Entity_CATEGORY_SUBJECT // Default
	if strategy.EntityType == types.EntityTypeEnvironment {
		category = entity.Entity_CATEGORY_ENVIRONMENT
	}

	// Create entity based on available claims
	// Priority: username > email > client_id > subject
	var entityV2 *entity.Entity

	if username, exists := result.Claims["username"]; exists {
		if usernameStr, ok := username.(string); ok && usernameStr != "" {
			entityV2 = &entity.Entity{
				EntityType: &entity.Entity_UserName{UserName: usernameStr},
				Category:   category,
			}
		}
	}

	if entityV2 == nil {
		if email, exists := result.Claims["email_address"]; exists {
			if emailStr, ok := email.(string); ok && emailStr != "" {
				entityV2 = &entity.Entity{
					EntityType: &entity.Entity_EmailAddress{EmailAddress: emailStr},
					Category:   category,
				}
			}
		}
	}

	if entityV2 == nil {
		if clientID, exists := result.Claims["client_id"]; exists {
			if clientIDStr, ok := clientID.(string); ok && clientIDStr != "" {
				entityV2 = &entity.Entity{
					EntityType: &entity.Entity_ClientId{ClientId: clientIDStr},
					Category:   category,
				}
			}
		}
	}

	if entityV2 == nil {
		if subject, exists := result.Claims["subject"]; exists {
			if subjectStr, ok := subject.(string); ok && subjectStr != "" {
				entityV2 = &entity.Entity{
					EntityType: &entity.Entity_UserName{UserName: subjectStr},
					Category:   category,
				}
			}
		}
	}

	// Fallback: use token ID as username if no suitable claim found
	if entityV2 == nil {
		ers.logger.WarnContext(ctx, "no suitable entity type found in claims, using token ID as fallback",
			slog.String("token_id", tokenID),
			slog.Any("available_claims", extractClaimNames(types.JWTClaims(result.Claims))))
		entityV2 = &entity.Entity{
			EntityType: &entity.Entity_UserName{UserName: tokenID},
			Category:   category,
		}
	}

	// Generate entity ID: strategy-tokenid-type-value
	entityID := fmt.Sprintf("%s-%s-%s-%s",
		strategy.Name,
		tokenID,
		getEntityTypeStringV2(entityV2),
		getEntityValueV2(entityV2.GetEntityType()))

	// Set the EphemeralId on the entity
	entityV2.EphemeralId = entityID
	return entityV2
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
	default:
		return "unknown"
	}
}

func getEntityValueV2(entityType interface{}) string {
	switch et := entityType.(type) {
	case *entity.Entity_UserName:
		return et.UserName
	case *entity.Entity_EmailAddress:
		return et.EmailAddress
	case *entity.Entity_ClientId:
		return et.ClientId
	default:
		return "unknown"
	}
}

// RegisterMultiStrategyERSV2 registers the v2 multi-strategy ERS service
func RegisterERSV2(config map[string]interface{}, logger *logger.Logger) (*ERSV2, serviceregistry.HandlerServer) {
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

// extractClaimNames extracts the names of claims from JWTClaims for logging
func extractClaimNames(claims types.JWTClaims) []string {
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	return names
}
