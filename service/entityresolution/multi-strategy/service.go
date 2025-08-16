package multistrategy

import (
	"context"
	"log/slog"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/providers/claims"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/providers/ldap"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/providers/sql"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
)

// Service implements the multi-strategy entity resolution service
type Service struct {
	config           types.MultiStrategyConfig
	providerRegistry *ProviderRegistry
	strategyMatcher  *StrategyMatcher
	logger           *logger.Logger
}

// NewService creates a new multi-strategy entity resolution service
func NewService(ctx context.Context, config types.MultiStrategyConfig, logger *logger.Logger) (*Service, error) {
	// Create provider registry
	registry := NewProviderRegistry()

	// Initialize providers based on configuration
	if err := initializeProviders(ctx, logger, registry, config.Providers); err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeConfiguration,
			"failed to initialize providers",
			err,
			map[string]interface{}{
				"provider_count": len(config.Providers),
			},
		)
	}

	// Create strategy matcher
	strategyMatcher := NewStrategyMatcher(config.MappingStrategies)

	service := &Service{
		config:           config,
		providerRegistry: registry,
		strategyMatcher:  strategyMatcher,
		logger:           logger,
	}

	return service, nil
}

// GetStrategyMatcher returns the strategy matcher for external access
func (s *Service) GetStrategyMatcher() *StrategyMatcher {
	return s.strategyMatcher
}

// GetConfig returns the configuration for external access
func (s *Service) GetConfig() types.MultiStrategyConfig {
	return s.config
}

// ResolveEntity resolves entity information using the configured strategies
func (s *Service) ResolveEntity(ctx context.Context, entityID string, jwtClaims types.JWTClaims) (*types.EntityResult, error) {
	// Get all matching strategies based on JWT claims
	strategies, err := s.strategyMatcher.SelectStrategies(ctx, jwtClaims)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeStrategy,
			"failed to select strategies",
			err,
			map[string]interface{}{
				"entity_id":  entityID,
				"jwt_claims": extractClaimNames(jwtClaims),
			},
		)
	}

	var lastError error
	var attemptedStrategies []string

	// Get global failure strategy
	failureStrategy := s.config.FailureStrategy
	if failureStrategy == "" {
		failureStrategy = types.FailureStrategyFailFast
	}

	// Try each matching strategy based on global failure strategy configuration
	for _, strategy := range strategies {
		attemptedStrategies = append(attemptedStrategies, strategy.Name)

		result, err := s.executeStrategy(ctx, entityID, jwtClaims, strategy)
		if err != nil {
			lastError = err

			// If fail-fast, return error immediately
			if failureStrategy == types.FailureStrategyFailFast {
				return nil, types.WrapMultiStrategyError(
					types.ErrorTypeStrategy,
					"strategy execution failed with global fail-fast policy",
					err,
					map[string]interface{}{
						"entity_id":            entityID,
						"strategy":             strategy.Name,
						"failure_strategy":     failureStrategy,
						"attempted_strategies": attemptedStrategies,
					},
				)
			}

			// Continue to next strategy (global continue policy)
			continue
		}

		// Success - add strategy metadata and return result
		result.Metadata["strategy_name"] = strategy.Name
		result.Metadata["strategy_provider"] = strategy.Provider
		result.Metadata["entity_type"] = strategy.EntityType
		result.Metadata["failure_strategy"] = failureStrategy
		result.Metadata["attempted_strategies"] = attemptedStrategies

		return result, nil
	}

	// All strategies failed
	return nil, types.WrapMultiStrategyError(
		types.ErrorTypeStrategy,
		"all matching strategies failed",
		lastError,
		map[string]interface{}{
			"entity_id":            entityID,
			"failure_strategy":     failureStrategy,
			"attempted_strategies": attemptedStrategies,
			"jwt_claims":           extractClaimNames(jwtClaims),
		},
	)
}

// HealthCheck performs health checks on all providers
func (s *Service) HealthCheck(ctx context.Context) error {
	providers := s.providerRegistry.GetAllProviders()

	var healthErrors []error

	for name, provider := range providers {
		if err := provider.HealthCheck(ctx); err != nil {
			healthErrors = append(healthErrors, types.WrapMultiStrategyError(
				types.ErrorTypeHealth,
				"provider health check failed",
				err,
				map[string]interface{}{
					"provider_name": name,
					"provider_type": provider.Type(),
				},
			))
		}
	}

	if len(healthErrors) > 0 {
		return types.NewHealthError("one or more providers failed health check", map[string]interface{}{
			"failed_providers": len(healthErrors),
			"total_providers":  len(providers),
			"errors":           healthErrors,
		})
	}

	return nil
}

// Close closes all providers and cleans up resources
func (s *Service) Close() error {
	return s.providerRegistry.Close()
}

// GetStrategies returns the configured mapping strategies
func (s *Service) GetStrategies() []types.MappingStrategy {
	return s.config.MappingStrategies
}

// GetProviders returns information about registered providers
func (s *Service) GetProviders() map[string]string {
	providers := s.providerRegistry.GetAllProviders()
	result := make(map[string]string)

	for name, provider := range providers {
		result[name] = provider.Type()
	}

	return result
}

// executeStrategy executes a single mapping strategy
func (s *Service) executeStrategy(ctx context.Context, entityID string, jwtClaims types.JWTClaims, strategy *types.MappingStrategy) (*types.EntityResult, error) {
	// Get provider for this strategy
	provider, err := s.providerRegistry.GetProvider(strategy.Provider)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"provider not found for strategy",
			err,
			map[string]interface{}{
				"strategy":  strategy.Name,
				"provider":  strategy.Provider,
				"entity_id": entityID,
			},
		)
	}

	// Extract parameters from JWT claims using input mapping
	mapper := &BaseMapper{}
	params, err := mapper.ExtractParameters(jwtClaims, strategy.InputMapping)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeMapping,
			"failed to extract parameters from JWT claims",
			err,
			map[string]interface{}{
				"strategy":      strategy.Name,
				"provider":      strategy.Provider,
				"entity_id":     entityID,
				"input_mapping": strategy.InputMapping,
			},
		)
	}

	// Call provider to resolve entity
	rawResult, err := provider.ResolveEntity(ctx, *strategy, params)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"provider failed to resolve entity",
			err,
			map[string]interface{}{
				"strategy":   strategy.Name,
				"provider":   strategy.Provider,
				"entity_id":  entityID,
				"parameters": params,
			},
		)
	}

	// Map raw result to entity result using output mapping
	outputMapper := &OutputMapper{}
	entityResult, err := outputMapper.MapResult(rawResult, strategy.OutputMapping, entityID)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeMapping,
			"failed to map provider result to entity",
			err,
			map[string]interface{}{
				"strategy":       strategy.Name,
				"provider":       strategy.Provider,
				"entity_id":      entityID,
				"output_mapping": strategy.OutputMapping,
			},
		)
	}

	return entityResult, nil
}

// initializeProviders creates and registers providers based on configuration
func initializeProviders(ctx context.Context, logger *logger.Logger, registry *ProviderRegistry, providerConfigs map[string]types.ProviderConfig) error {
	for name, config := range providerConfigs {
		var provider types.Provider
		var err error

		switch config.Type {
		case "claims":
			// Create claims provider
			claimsConfig := claims.Config{
				Description: "JWT claims provider: " + name,
			}
			provider, err = claims.NewProvider(name, claimsConfig)

		case "sql":
			// Parse SQL configuration
			sqlConfig := parseSQLConfig(config.Connection)
			provider, err = sql.NewProvider(ctx, name, sqlConfig)

		case "ldap":
			// Parse LDAP configuration
			ldapConfig := parseLDAPConfig(config.Connection)
			provider, err = ldap.NewProvider(ctx, name, ldapConfig)

		default:
			return types.NewConfigurationError(
				"unknown provider type: "+config.Type,
				map[string]interface{}{
					"provider_name": name,
					"provider_type": config.Type,
				},
			)
		}

		if err != nil {
			return types.WrapMultiStrategyError(
				types.ErrorTypeProvider,
				"failed to create provider",
				err,
				map[string]interface{}{
					"provider_name": name,
					"provider_type": config.Type,
				},
			)
		}

		// Register the provider
		if err := registry.RegisterProvider(name, provider); err != nil {
			// Clean up the provider if registration fails
			if closeErr := provider.Close(); closeErr != nil {
				logger.Error("failed to close provider",
					slog.String("provider_name", name),
					slog.String("provider_type", config.Type),
					slog.String("error", closeErr.Error()))
			}
			return types.WrapMultiStrategyError(
				types.ErrorTypeConfiguration,
				"failed to register provider",
				err,
				map[string]interface{}{
					"provider_name": name,
					"provider_type": config.Type,
				},
			)
		}
	}

	return nil
}

// parseSQLConfig converts generic connection config to SQL-specific config
func parseSQLConfig(connectionConfig map[string]interface{}) sql.Config {
	config := sql.DefaultConfig()

	// Parse required fields
	if driver, ok := connectionConfig["driver"].(string); ok {
		config.Driver = driver
	}
	if host, ok := connectionConfig["host"].(string); ok {
		config.Host = host
	}
	if port, ok := connectionConfig["port"].(int); ok {
		config.Port = port
	}
	if database, ok := connectionConfig["database"].(string); ok {
		config.Database = database
	}
	if username, ok := connectionConfig["username"].(string); ok {
		config.Username = username
	}
	if password, ok := connectionConfig["password"].(string); ok {
		config.Password = password
	}
	if sslMode, ok := connectionConfig["ssl_mode"].(string); ok {
		config.SSLMode = sslMode
	}
	if desc, ok := connectionConfig["description"].(string); ok {
		config.Description = desc
	}

	return config
}

// parseLDAPConfig converts generic connection config to LDAP-specific config
func parseLDAPConfig(connectionConfig map[string]interface{}) ldap.Config {
	config := ldap.DefaultConfig()

	// Parse required fields
	if host, ok := connectionConfig["host"].(string); ok {
		config.Host = host
	}
	if port, ok := connectionConfig["port"].(int); ok {
		config.Port = port
	}
	if useTLS, ok := connectionConfig["use_tls"].(bool); ok {
		config.UseTLS = useTLS
	}
	if bindDN, ok := connectionConfig["bind_dn"].(string); ok {
		config.BindDN = bindDN
	}
	if bindPassword, ok := connectionConfig["bind_password"].(string); ok {
		config.BindPassword = bindPassword
	}
	if desc, ok := connectionConfig["description"].(string); ok {
		config.Description = desc
	}

	return config
}
