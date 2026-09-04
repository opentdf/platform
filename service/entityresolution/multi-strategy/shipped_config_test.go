package multistrategy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// shippedERSConfig loads the multi-strategy block out of opentdf-ers-test.yaml, the
// repo-root config the README tells operators to start the platform with
// (`go run ./service start --config opentdf-ers-test.yaml`).
func shippedERSConfig(t *testing.T) types.MultiStrategyConfig {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "opentdf-ers-test.yaml"))
	require.NoError(t, err)

	var root struct {
		EntityResolution struct {
			Type   string                 `yaml:"type"`
			Config map[string]interface{} `yaml:"config"`
		} `yaml:"entityresolution"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &root))
	require.Equal(t, "multi-strategy", root.EntityResolution.Type)
	require.NotEmpty(t, root.EntityResolution.Config, "entityresolution.config block not found")

	var config types.MultiStrategyConfig
	require.NoError(t, mapstructure.Decode(root.EntityResolution.Config, &config))
	require.NotEmpty(t, config.MappingStrategies)
	return config
}

// keycloakStyleClaims mirrors the claims on a Keycloak access token. Every Keycloak token
// carries "azp" (authorized party), whether it came from a user login or client credentials.
func keycloakStyleClaims() types.JWTClaims {
	return types.JWTClaims{
		"sub":                "37c8ec42-ec2d-4b3b-8c2d-3c8b6c1c2f11",
		"azp":                "opentdf-sdk",
		"preferred_username": "alice",
		"email":              "alice@example.com",
	}
}

// TestShippedERSConfigSelectsEnvironmentStrategyFirst shows the environment-first ordering is
// not hypothetical: the config this repo ships and documents lists an entity_type: environment
// strategy conditioned on "azp exists" ahead of every subject strategy, and "azp" is present on
// every Keycloak token. Combined with first-match-wins chain building, the chain such a token
// produces holds only an ENVIRONMENT entity.
func TestShippedERSConfigSelectsEnvironmentStrategyFirst(t *testing.T) {
	config := shippedERSConfig(t)
	require.Equal(t, types.FailureStrategyContinue, config.FailureStrategy)

	matcher := NewStrategyMatcher(config.MappingStrategies)
	matched, err := matcher.SelectStrategies(t.Context(), keycloakStyleClaims())
	require.NoError(t, err)
	require.NotEmpty(t, matched)

	require.Equal(t, "client_environment_sql", matched[0].Name)
	require.Equal(t, types.EntityTypeEnvironment, matched[0].EntityType,
		"first matching strategy resolves an environment entity, so first-match-wins yields an environment-only chain")

	// Subject strategies do match this token; they are just never reached.
	var subjectNames []string
	for _, strategy := range matched[1:] {
		if strategy.EntityType == types.EntityTypeSubject {
			subjectNames = append(subjectNames, strategy.Name)
		}
	}
	require.NotEmpty(t, subjectNames, "subject strategies match but are skipped after the first success")
}

// TestShippedERSConfigHasNoOrderingGuard records that nothing in configuration handling
// prevents this: entity_type is read only when building the entity, never validated, and
// SelectStrategies preserves configuration order rather than preferring subject strategies.
func TestShippedERSConfigHasNoOrderingGuard(t *testing.T) {
	config := shippedERSConfig(t)

	// Reordering the same strategies changes which entity the chain gets, so ordering is
	// load-bearing configuration with no validation behind it.
	reversed := make([]types.MappingStrategy, 0, len(config.MappingStrategies))
	for i := len(config.MappingStrategies) - 1; i >= 0; i-- {
		reversed = append(reversed, config.MappingStrategies[i])
	}

	matched, err := NewStrategyMatcher(reversed).SelectStrategies(t.Context(), keycloakStyleClaims())
	require.NoError(t, err)
	require.Equal(t, types.EntityTypeSubject, matched[0].EntityType)
}
