package multistrategy

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
)

// validateConfig checks output mappings at startup so misconfiguration surfaces at
// boot rather than as a per-request failure or a silently dropped claim.
func validateConfig(config types.MultiStrategyConfig, log *logger.Logger) error {
	for _, strategy := range config.MappingStrategies {
		if err := validateOutputMappings(strategy, log); err != nil {
			return fmt.Errorf("mapping strategy %q: %w", strategy.Name, err)
		}
	}
	return nil
}

func validateOutputMappings(strategy types.MappingStrategy, log *logger.Logger) error {
	supported := supportedTransformations()

	for idx, mapping := range strategy.OutputMapping {
		if err := validateClaimName(mapping.ClaimName); err != nil {
			return fmt.Errorf("output_mapping[%d]: %w", idx, err)
		}

		sources := configuredSourceFields(mapping)
		switch {
		case len(sources) == 0:
			return fmt.Errorf("output_mapping[%d] (claim_name %q): no source field specified; set one of source_column, source_attribute, source_claim or source_key",
				idx, mapping.ClaimName)
		case len(sources) > 1 && log != nil:
			// Not an error: the runtime resolves by precedence and shared config
			// templates legitimately set several
			log.Warn("output mapping specifies multiple source fields; only the first by precedence is used",
				slog.String("strategy", strategy.Name),
				slog.String("claim_name", mapping.ClaimName),
				slog.Any("source_fields", sources),
			)
		}

		if mapping.Transformation != "" && !slices.Contains(supported, strings.ToLower(mapping.Transformation)) {
			return fmt.Errorf("output_mapping[%d] (claim_name %q): unknown transformation %q; supported: %s",
				idx, mapping.ClaimName, mapping.Transformation, strings.Join(supported, ", "))
		}
	}

	return validateNoOverlappingClaimNames(strategy.OutputMapping)
}

func validateClaimName(claimName string) error {
	if claimName == "" {
		return errors.New("claim_name is required")
	}
	for _, segment := range strings.Split(claimName, ".") {
		if strings.TrimSpace(segment) == "" {
			return fmt.Errorf("claim_name %q has an empty path segment", claimName)
		}
	}
	return nil
}

// validateNoOverlappingClaimNames rejects duplicates and prefix overlaps, which would
// otherwise clobber each other or fail depending on mapping order.
func validateNoOverlappingClaimNames(mappings []types.OutputMapping) error {
	for i, a := range mappings {
		aParts := strings.Split(a.ClaimName, ".")
		for _, b := range mappings[i+1:] {
			if a.ClaimName == b.ClaimName {
				return fmt.Errorf("duplicate claim_name %q", a.ClaimName)
			}
			bParts := strings.Split(b.ClaimName, ".")
			if isClaimPathPrefix(aParts, bParts) {
				return fmt.Errorf("claim_name %q is a path prefix of %q", a.ClaimName, b.ClaimName)
			}
			if isClaimPathPrefix(bParts, aParts) {
				return fmt.Errorf("claim_name %q is a path prefix of %q", b.ClaimName, a.ClaimName)
			}
		}
	}
	return nil
}

func isClaimPathPrefix(short, long []string) bool {
	if len(short) >= len(long) {
		return false
	}
	for i, segment := range short {
		if segment != long[i] {
			return false
		}
	}
	return true
}

// configuredSourceFields returns the set source fields, in resolution precedence order.
func configuredSourceFields(mapping types.OutputMapping) []string {
	var fields []string
	if mapping.SourceColumn != "" {
		fields = append(fields, "source_column")
	}
	if mapping.SourceAttribute != "" {
		fields = append(fields, "source_attribute")
	}
	if mapping.SourceClaim != "" {
		fields = append(fields, "source_claim")
	}
	if mapping.SourceKey != "" {
		fields = append(fields, "source_key")
	}
	return fields
}
