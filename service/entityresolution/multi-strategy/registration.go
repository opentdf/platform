package multistrategy

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/structpb"
)

// MultiStrategyERS implements the EntityResolutionServiceHandler for multi-strategy resolution
type MultiStrategyERS struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	service *Service
	logger  *logger.Logger
	trace.Tracer
}

// NewMultiStrategyERS creates a new multi-strategy ERS
func NewMultiStrategyERS(config types.MultiStrategyConfig, logger *logger.Logger) (*MultiStrategyERS, error) {
	service, err := NewService(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create multi-strategy service: %w", err)
	}

	return &MultiStrategyERS{
		service: service,
		logger:  logger,
	}, nil
}

// ResolveEntities implements the EntityResolutionServiceHandler interface
func (ers *MultiStrategyERS) ResolveEntities(
	ctx context.Context,
	req *connect.Request[entityresolution.ResolveEntitiesRequest],
) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
	// Extract JWT claims from context (this would be set by authentication middleware)
	jwtClaims, ok := ctx.Value("jwt_claims").(types.JWTClaims)
	if !ok {
		ers.logger.Warn("No JWT claims found in context for multi-strategy ERS")
		jwtClaims = make(types.JWTClaims)
	}

	payload := req.Msg.GetEntities()
	resolvedEntities := make([]*entityresolution.EntityRepresentation, 0, len(payload))

	for _, entity := range payload {
		entityID := entity.GetId()
		if entityID == "" {
			ers.logger.Warn("Empty entity ID in request")
			continue
		}

		// Resolve entity using multi-strategy service
		result, err := ers.service.ResolveEntity(ctx, entityID, jwtClaims)
		if err != nil {
			ers.logger.Error("Failed to resolve entity",
				"entity_id", entityID,
				"error", err.Error())

			// Create error struct
			errorStruct, structErr := structpb.NewStruct(map[string]interface{}{
				"error":     err.Error(),
				"entity_id": entityID,
			})
			if structErr != nil {
				ers.logger.Error("Failed to create error struct", "error", structErr.Error())
				continue
			}

			resolvedEntities = append(resolvedEntities, &entityresolution.EntityRepresentation{
				OriginalId:      entityID,
				AdditionalProps: []*structpb.Struct{errorStruct},
			})
			continue
		}

		// Convert multi-strategy result to protocol format
		resultData := make(map[string]interface{})

		// Add resolved claims
		for claimName, claimValue := range result.Claims {
			resultData[claimName] = claimValue
		}

		// Add metadata with "metadata_" prefix
		for metaKey, metaValue := range result.Metadata {
			resultData[fmt.Sprintf("metadata_%s", metaKey)] = metaValue
		}

		// Convert to protobuf struct
		resultStruct, structErr := structpb.NewStruct(resultData)
		if structErr != nil {
			ers.logger.Error("Failed to create result struct",
				"entity_id", entityID,
				"error", structErr.Error())
			continue
		}

		resolvedEntities = append(resolvedEntities, &entityresolution.EntityRepresentation{
			OriginalId:      entityID,
			AdditionalProps: []*structpb.Struct{resultStruct},
		})
	}

	return connect.NewResponse(&entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}), nil
}

// CreateEntityChainFromJwt implements the EntityResolutionServiceHandler interface
func (ers *MultiStrategyERS) CreateEntityChainFromJwt(
	ctx context.Context,
	req *connect.Request[entityresolution.CreateEntityChainFromJwtRequest],
) (*connect.Response[entityresolution.CreateEntityChainFromJwtResponse], error) {
	// Skip tracing for now to avoid nil pointer issues
	// TODO: Initialize tracer properly in constructor

	entityChains := make([]*authorization.EntityChain, 0, len(req.Msg.GetTokens()))

	// FAIL-SAFE: If ANY token fails to create a complete entity chain, fail the entire request
	// This ensures authorization decisions are made with complete identity context
	for _, token := range req.Msg.GetTokens() {
		entityChain, err := ers.createEntityChainFromSingleToken(ctx, token)
		if err != nil {
			ers.logger.ErrorContext(ctx, "Failed to create entity chain from token - FAILING REQUEST for security",
				"token_id", token.GetId(),
				"error", err.Error())
			return nil, connect.NewError(connect.CodeInternal, 
				fmt.Errorf("failed to create entity chain for token %s: %w", token.GetId(), err))
		}
		
		// Validate that we have at least one entity in the chain
		if len(entityChain.Entities) == 0 {
			ers.logger.ErrorContext(ctx, "Entity chain is empty - FAILING REQUEST for security",
				"token_id", token.GetId())
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("entity chain for token %s is empty - incomplete identity context", token.GetId()))
		}
		
		entityChains = append(entityChains, entityChain)
	}

	ers.logger.DebugContext(ctx, "Successfully created entity chains",
		"chain_count", len(entityChains),
		"total_entities", ers.countEntitiesInChains(entityChains))

	return connect.NewResponse(&entityresolution.CreateEntityChainFromJwtResponse{
		EntityChains: entityChains,
	}), nil
}

// createEntityChainFromSingleToken processes a single JWT token using multi-strategy resolution
func (ers *MultiStrategyERS) createEntityChainFromSingleToken(ctx context.Context, token *authorization.Token) (*authorization.EntityChain, error) {
	// Parse JWT to extract claims
	jwtClaims, err := ers.parseJWTClaims(token.GetJwt())
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeMapping,
			"failed to parse JWT token",
			err,
			map[string]interface{}{
				"token_id": token.GetId(),
			},
		)
	}

	// Get matching strategies for these JWT claims
	strategies, err := ers.service.strategyMatcher.SelectStrategies(ctx, jwtClaims)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeStrategy,
			"failed to select strategies for JWT claims",
			err,
			map[string]interface{}{
				"token_id": token.GetId(),
				"jwt_claims": extractClaimNames(jwtClaims),
			},
		)
	}

	if len(strategies) == 0 {
		return nil, types.NewConfigurationError(
			"no matching strategies found for JWT claims",
			map[string]interface{}{
				"token_id": token.GetId(),
				"jwt_claims": extractClaimNames(jwtClaims),
			},
		)
	}

	entities := make([]*authorization.Entity, 0)
	var lastError error
	var attemptedStrategies []string

	// Try strategies based on service-level failure strategy configuration
	failureStrategy := ers.service.config.FailureStrategy
	if failureStrategy == "" {
		failureStrategy = types.FailureStrategyFailFast
	}

	for _, strategy := range strategies {
		attemptedStrategies = append(attemptedStrategies, strategy.Name)
		
		// Resolve entity using this strategy
		entityResult, err := ers.service.ResolveEntity(ctx, token.GetId(), jwtClaims)
		if err != nil {
			lastError = err
			ers.logger.WarnContext(ctx, "Strategy failed for token",
				"token_id", token.GetId(),
				"strategy", strategy.Name,
				"error", err.Error())
			
			// If fail-fast, return error immediately
			if failureStrategy == types.FailureStrategyFailFast {
				return nil, types.WrapMultiStrategyError(
					types.ErrorTypeStrategy,
					"strategy execution failed with fail-fast policy",
					err,
					map[string]interface{}{
						"token_id": token.GetId(),
						"strategy": strategy.Name,
						"failure_strategy": failureStrategy,
						"attempted_strategies": attemptedStrategies,
					},
				)
			}
			
			// Continue to next strategy
			continue
		}

		// Success! Create entity from result
		entity := ers.createEntityFromResult(entityResult, strategy, token.GetId())
		entities = append(entities, entity)

		ers.logger.DebugContext(ctx, "Successfully resolved entity for token",
			"token_id", token.GetId(),
			"strategy", strategy.Name,
			"entity_type", getEntityTypeString(entity),
			"entity_category", entity.Category.String())
		
		// For now, we create one entity per successful strategy
		// TODO: Consider if we should try multiple strategies and combine results
		break
	}

	// If no strategies succeeded
	if len(entities) == 0 {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeStrategy,
			"all strategies failed for token",
			lastError,
			map[string]interface{}{
				"token_id": token.GetId(),
				"failure_strategy": failureStrategy,
				"attempted_strategies": attemptedStrategies,
				"jwt_claims": extractClaimNames(jwtClaims),
			},
		)
	}

	return &authorization.EntityChain{
		Id:       token.GetId(),
		Entities: entities,
	}, nil
}

// createEntityFromResult converts a multi-strategy EntityResult to an authorization Entity
func (ers *MultiStrategyERS) createEntityFromResult(result *types.EntityResult, strategy *types.MappingStrategy, tokenId string) *authorization.Entity {
	// Determine entity category based on strategy configuration
	category := authorization.Entity_CATEGORY_SUBJECT // Default
	if strategy.EntityType == types.EntityTypeEnvironment {
		category = authorization.Entity_CATEGORY_ENVIRONMENT
	}

	// Create entity based on available claims
	// Priority: username > email > client_id > subject
	var entity *authorization.Entity
	
	if username, exists := result.Claims["username"]; exists {
		if usernameStr, ok := username.(string); ok && usernameStr != "" {
			entity = &authorization.Entity{
				EntityType: &authorization.Entity_UserName{UserName: usernameStr},
				Category:   category,
			}
		}
	}
	
	if entity == nil {
		if email, exists := result.Claims["email_address"]; exists {
			if emailStr, ok := email.(string); ok && emailStr != "" {
				entity = &authorization.Entity{
					EntityType: &authorization.Entity_EmailAddress{EmailAddress: emailStr},
					Category:   category,
				}
			}
		}
	}
	
	if entity == nil {
		if clientId, exists := result.Claims["client_id"]; exists {
			if clientIdStr, ok := clientId.(string); ok && clientIdStr != "" {
				entity = &authorization.Entity{
					EntityType: &authorization.Entity_ClientId{ClientId: clientIdStr},
					Category:   category,
				}
			}
		}
	}
	
	if entity == nil {
		if subject, exists := result.Claims["subject"]; exists {
			if subjectStr, ok := subject.(string); ok && subjectStr != "" {
				entity = &authorization.Entity{
					EntityType: &authorization.Entity_UserName{UserName: subjectStr},
					Category:   category,
				}
			}
		}
	}

	// Fallback: use token ID as username if no suitable claim found
	if entity == nil {
		ers.logger.WarnContext(context.Background(), "No suitable entity type found in claims, using token ID as fallback",
			"token_id", tokenId,
			"available_claims", extractClaimNames(types.JWTClaims(result.Claims)))
		entity = &authorization.Entity{
			EntityType: &authorization.Entity_UserName{UserName: tokenId},
			Category:   category,
		}
	}

	// Generate entity ID: strategy-tokenid-type-value
	entityId := fmt.Sprintf("%s-%s-%s-%s", 
		strategy.Name, 
		tokenId, 
		getEntityTypeString(entity),
		getEntityValue(entity.EntityType))

	// Set the ID on the entity
	entity.Id = entityId
	return entity
}

// Helper functions
func (ers *MultiStrategyERS) parseJWTClaims(jwtString string) (types.JWTClaims, error) {
	// For now, use a simple JWT parser (in production, this should validate signatures)
	// This is similar to how Keycloak ERS parses JWTs
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	
	claims, err := token.AsMap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}
	
	return types.JWTClaims(claims), nil
}

func (ers *MultiStrategyERS) countEntitiesInChains(chains []*authorization.EntityChain) int {
	total := 0
	for _, chain := range chains {
		total += len(chain.Entities)
	}
	return total
}

// extractClaimNames is defined in strategy_matcher.go, reusing that implementation

func getEntityTypeString(entity *authorization.Entity) string {
	switch entity.GetEntityType().(type) {
	case *authorization.Entity_UserName:
		return "username"
	case *authorization.Entity_EmailAddress:
		return "email"
	case *authorization.Entity_ClientId:
		return "client_id"
	default:
		return "unknown"
	}
}

func getEntityValue(entityType interface{}) string {
	switch et := entityType.(type) {
	case *authorization.Entity_UserName:
		return et.UserName
	case *authorization.Entity_EmailAddress:
		return et.EmailAddress
	case *authorization.Entity_ClientId:
		return et.ClientId
	default:
		return "unknown"
	}
}

// RegisterMultiStrategyERS registers the multi-strategy ERS service
func RegisterMultiStrategyERS(config map[string]interface{}, logger *logger.Logger) (*MultiStrategyERS, serviceregistry.HandlerServer) {
	var multiStrategyConfig types.MultiStrategyConfig

	if err := mapstructure.Decode(config, &multiStrategyConfig); err != nil {
		logger.Error("Failed to decode multi-strategy configuration", "error", err)
		panic(fmt.Sprintf("Failed to decode multi-strategy configuration: %v", err))
	}

	ers, err := NewMultiStrategyERS(multiStrategyConfig, logger)
	if err != nil {
		logger.Error("Failed to create multi-strategy ERS", "error", err)
		panic(fmt.Sprintf("Failed to create multi-strategy ERS: %v", err))
	}

	return ers, nil
}
