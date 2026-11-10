package claims

import (
	"context"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// Provider implements the Provider interface for JWT claims
type Provider struct {
	name   string
	config Config
	mapper types.Mapper
}

// NewProvider creates a new JWT claims provider
func NewProvider(name string, config Config) (*Provider, error) {
	return &Provider{
		name:   name,
		config: config,
		mapper: NewMapper(),
	}, nil
}

// Name returns the provider instance name
func (p *Provider) Name() string {
	return p.name
}

// Type returns the provider type
func (p *Provider) Type() string {
	return "claims"
}

// ResolveEntity extracts claims directly from JWT (passed via context)
func (p *Provider) ResolveEntity(ctx context.Context, strategy types.MappingStrategy, _ map[string]interface{}) (*types.RawResult, error) {
	// Extract JWT claims from context
	claims, ok := ctx.Value(types.JWTClaimsContextKey).(types.JWTClaims)
	if !ok || claims == nil {
		return nil, types.NewProviderError("JWT claims not found in context", map[string]interface{}{
			"provider": p.name,
			"strategy": strategy.Name,
		})
	}

	// Create result with all JWT claims
	result := &types.RawResult{
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	// Copy all JWT claims to result data
	for claimName, claimValue := range claims {
		result.Data[claimName] = claimValue
	}

	// Add metadata about the source
	result.Metadata["provider_type"] = "claims"
	result.Metadata["provider_name"] = p.name
	result.Metadata["source"] = "jwt_claims"
	result.Metadata["claim_count"] = len(claims)

	return result, nil
}

// HealthCheck always returns nil since JWT claims provider has no external dependencies
func (p *Provider) HealthCheck(_ context.Context) error {
	// JWT claims provider is always healthy - no external dependencies
	return nil
}

// GetMapper returns the provider's mapper implementation
func (p *Provider) GetMapper() types.Mapper {
	return p.mapper
}

// Close cleans up any resources (none for claims provider)
func (p *Provider) Close() error {
	// No resources to clean up
	return nil
}
