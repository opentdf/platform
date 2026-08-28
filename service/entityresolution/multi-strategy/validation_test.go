package multistrategy

import (
	"strings"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
)

func strategyWith(mappings ...types.OutputMapping) types.MultiStrategyConfig {
	return types.MultiStrategyConfig{
		MappingStrategies: []types.MappingStrategy{
			{Name: "test_strategy", Provider: "jwt_claims", OutputMapping: mappings},
		},
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      types.MultiStrategyConfig
		errContains string
	}{
		{
			name:   "empty config",
			config: types.MultiStrategyConfig{},
		},
		{
			name: "valid mappings",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "sub", ClaimName: "username"},
				types.OutputMapping{SourceClaim: "roles", ClaimName: "attributes.roles", Transformation: "array"},
				types.OutputMapping{SourceClaim: "nationality", ClaimName: "attributes.nationality"},
			),
		},
		{
			name:        "empty claim_name",
			config:      strategyWith(types.OutputMapping{SourceClaim: "sub"}),
			errContains: "claim_name is required",
		},
		{
			name:        "leading dot in claim_name",
			config:      strategyWith(types.OutputMapping{SourceClaim: "sub", ClaimName: ".a"}),
			errContains: "empty path segment",
		},
		{
			name:        "trailing dot in claim_name",
			config:      strategyWith(types.OutputMapping{SourceClaim: "sub", ClaimName: "a."}),
			errContains: "empty path segment",
		},
		{
			name:        "consecutive dots in claim_name",
			config:      strategyWith(types.OutputMapping{SourceClaim: "sub", ClaimName: "a..b"}),
			errContains: "empty path segment",
		},
		{
			name:        "whitespace-only segment in claim_name",
			config:      strategyWith(types.OutputMapping{SourceClaim: "sub", ClaimName: "a. .b"}),
			errContains: "empty path segment",
		},
		{
			name:        "no source field",
			config:      strategyWith(types.OutputMapping{ClaimName: "username"}),
			errContains: "no source field specified",
		},
		{
			name: "multiple source fields is not an error",
			config: strategyWith(types.OutputMapping{
				SourceColumn: "col", SourceClaim: "sub", ClaimName: "username",
			}),
		},
		{
			name: "duplicate claim_name",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "client_id", ClaimName: "client_id"},
				types.OutputMapping{SourceClaim: "azp", ClaimName: "client_id"},
			),
			errContains: `duplicate claim_name "client_id"`,
		},
		{
			name: "claim_name is a prefix of another",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "a", ClaimName: "attributes"},
				types.OutputMapping{SourceClaim: "b", ClaimName: "attributes.nationality"},
			),
			errContains: "is a path prefix of",
		},
		{
			name: "prefix overlap in reverse order",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "b", ClaimName: "attributes.nationality"},
				types.OutputMapping{SourceClaim: "a", ClaimName: "attributes"},
			),
			errContains: "is a path prefix of",
		},
		{
			name: "shared parent is not an overlap",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "a", ClaimName: "attributes.nationality"},
				types.OutputMapping{SourceClaim: "b", ClaimName: "attributes.clearance"},
			),
		},
		{
			name: "similar prefix on a segment boundary only",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "a", ClaimName: "attr"},
				types.OutputMapping{SourceClaim: "b", ClaimName: "attributes.nationality"},
			),
		},
		{
			name:        "unknown transformation",
			config:      strategyWith(types.OutputMapping{SourceClaim: "sub", ClaimName: "u", Transformation: "nope"}),
			errContains: `unknown transformation "nope"`,
		},
		{
			name: "transformation names are case-insensitive",
			config: strategyWith(
				types.OutputMapping{SourceClaim: "roles", ClaimName: "r", Transformation: "ARRAY"},
			),
		},
		{
			name: "errors name the offending strategy",
			config: types.MultiStrategyConfig{
				MappingStrategies: []types.MappingStrategy{
					{Name: "ok_strategy", OutputMapping: []types.OutputMapping{{SourceClaim: "sub", ClaimName: "u"}}},
					{Name: "bad_strategy", OutputMapping: []types.OutputMapping{{SourceClaim: "sub"}}},
				},
			},
			errContains: `mapping strategy "bad_strategy"`,
		},
	}

	log := logger.CreateTestLogger()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config, log)

			if tt.errContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.errContains)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error = %q, expected it to contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

// TestValidateConfig_SupportedTransformationsMatchRuntime keeps the validator's list
// from drifting away from what applyTransformation actually accepts.
func TestValidateConfig_SupportedTransformationsMatchRuntime(t *testing.T) {
	om := NewOutputMapper()
	log := logger.CreateTestLogger()

	for _, transformation := range supportedTransformations() {
		t.Run(transformation, func(t *testing.T) {
			if _, err := om.applyTransformation("value", transformation); err != nil &&
				strings.Contains(err.Error(), "unknown transformation") {
				t.Errorf("%q passes validation but the runtime rejects it", transformation)
			}

			config := strategyWith(types.OutputMapping{
				SourceClaim: "sub", ClaimName: "c", Transformation: transformation,
			})
			if err := validateConfig(config, log); err != nil {
				t.Errorf("%q is supported at runtime but fails validation: %v", transformation, err)
			}
		})
	}
}

func TestNewService_RejectsInvalidConfig(t *testing.T) {
	config := strategyWith(types.OutputMapping{SourceClaim: "sub", ClaimName: "a..b"})

	_, err := NewService(t.Context(), config, logger.CreateTestLogger())
	if err == nil {
		t.Fatal("expected NewService to reject an invalid output mapping")
	}
	if !strings.Contains(err.Error(), "invalid multi-strategy configuration") {
		t.Errorf("error = %q, expected it to report an invalid configuration", err.Error())
	}
}
