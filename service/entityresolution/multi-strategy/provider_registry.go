package multistrategy

import (
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// ProviderRegistry manages provider instances
type ProviderRegistry struct {
	providers map[string]types.Provider
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]types.Provider),
	}
}

// RegisterProvider registers a provider instance
func (r *ProviderRegistry) RegisterProvider(name string, provider types.Provider) error {
	if _, exists := r.providers[name]; exists {
		return types.NewMultiStrategyError(types.ErrorTypeConfiguration, "provider already registered", map[string]interface{}{
			"provider_name": name,
		})
	}

	r.providers[name] = provider
	return nil
}

// GetProvider retrieves a provider by name
func (r *ProviderRegistry) GetProvider(name string) (types.Provider, error) {
	provider, exists := r.providers[name]
	if !exists {
		return nil, types.NewMultiStrategyError(types.ErrorTypeConfiguration, "provider not found", map[string]interface{}{
			"provider_name": name,
		})
	}

	return provider, nil
}

// GetAllProviders returns all registered providers
func (r *ProviderRegistry) GetAllProviders() map[string]types.Provider {
	result := make(map[string]types.Provider)
	for name, provider := range r.providers {
		result[name] = provider
	}
	return result
}

// Close closes all providers
func (r *ProviderRegistry) Close() error {
	var errors []error

	for name, provider := range r.providers {
		if err := provider.Close(); err != nil {
			errors = append(errors, types.NewMultiStrategyError(types.ErrorTypeProvider, "failed to close provider", map[string]interface{}{
				"provider_name": name,
				"error":         err.Error(),
			}))
		}
	}

	if len(errors) > 0 {
		return types.NewMultiStrategyError(types.ErrorTypeProvider, "failed to close some providers", map[string]interface{}{
			"error_count": len(errors),
			"errors":      errors,
		})
	}

	return nil
}
