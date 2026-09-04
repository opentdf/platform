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

// TestShippedERSConfigResolvesASubjectForKeycloakToken is the second failing test, and it is
// what makes the bug operator-facing rather than theoretical.
//
// Under first-match-wins the strategy that wins is the first one whose conditions match, so a
// config is only usable for decisions if that winner resolves a subject entity. The config
// this repo ships and documents (README: `go run ./service start --config
// opentdf-ers-test.yaml`) fails that: client_environment_sql is entity_type: environment,
// conditioned on "azp exists", and listed ahead of every subject strategy. Every Keycloak
// token carries azp, so every token loses its subject entity.
//
// Fixable either by reordering the YAML or by making strategy order stop deciding the entity
// category; this test does not care which.
func TestShippedERSConfigResolvesASubjectForKeycloakToken(t *testing.T) {
	config := shippedERSConfig(t)
	require.Equal(t, types.FailureStrategyContinue, config.FailureStrategy)

	matched, err := NewStrategyMatcher(config.MappingStrategies).SelectStrategies(t.Context(), keycloakStyleClaims())
	require.NoError(t, err)
	require.NotEmpty(t, matched)

	require.Equal(t, types.EntityTypeSubject, matched[0].EntityType,
		"winning strategy %q resolves an %s entity, so a Keycloak token produces a chain with no subject; matched order was %v",
		matched[0].Name, matched[0].EntityType, strategyNames(matched))
}

// TestShippedERSConfigOrderingIsUnvalidated is the supporting observation, and it passes:
// nothing rejects or normalizes the ordering. entity_type is never validated, and
// SelectStrategies preserves configuration order rather than preferring subject strategies,
// so simply reversing the same strategies changes which entity a token resolves to.
func TestShippedERSConfigOrderingIsUnvalidated(t *testing.T) {
	config := shippedERSConfig(t)

	reversed := make([]types.MappingStrategy, 0, len(config.MappingStrategies))
	for i := len(config.MappingStrategies) - 1; i >= 0; i-- {
		reversed = append(reversed, config.MappingStrategies[i])
	}

	matched, err := NewStrategyMatcher(reversed).SelectStrategies(t.Context(), keycloakStyleClaims())
	require.NoError(t, err)
	require.Equal(t, types.EntityTypeSubject, matched[0].EntityType,
		"the same strategies in the opposite order win with a subject entity")
}

func strategyNames(strategies []*types.MappingStrategy) []string {
	names := make([]string, 0, len(strategies))
	for _, strategy := range strategies {
		names = append(names, strategy.Name+"="+strategy.EntityType)
	}
	return names
}
