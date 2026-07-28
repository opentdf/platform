package audit

import (
	"fmt"
	"strings"
)

// JWTClaimMapping maps a JWT claim to a destination in the emitted audit log.
// The destination path uses dot notation over the audit log output shape, e.g.
// `eventMetaData.requester.sub`.
type JWTClaimMapping struct {
	Claim string `mapstructure:"claim" json:"claim"`
	Path  string `mapstructure:"path" json:"path"`
}

// Config contains platform-wide audit configuration.
type Config struct {
	// JWTClaimMappings writes JWT claims to configured destinations in the audit
	// log output, preserving the original JSON value types where possible.
	JWTClaimMappings []JWTClaimMapping `mapstructure:"jwt_claim_mappings" json:"jwt_claim_mappings"`
}

func (c Config) Validate() error {
	for idx, mapping := range c.JWTClaimMappings {
		if mapping.Claim == "" {
			return fmt.Errorf("jwt_claim_mappings[%d].claim is required", idx)
		}
		if mapping.Path == "" {
			return fmt.Errorf("jwt_claim_mappings[%d].path is required", idx)
		}
		if err := validateClaimDestinationPath(mapping.Path); err != nil {
			return fmt.Errorf("jwt_claim_mappings[%d].path: %w", idx, err)
		}
	}
	if err := validateNoOverlappingPaths(c.JWTClaimMappings); err != nil {
		return err
	}
	return nil
}

func validateNoOverlappingPaths(mappings []JWTClaimMapping) error {
	for i, a := range mappings {
		aParts := strings.Split(a.Path, ".")
		for j, b := range mappings {
			if i >= j {
				continue
			}
			if a.Path == b.Path {
				return fmt.Errorf("%w: duplicate path %q", ErrOverlappingAuditPaths, a.Path)
			}
			bParts := strings.Split(b.Path, ".")
			if isPathPrefix(aParts, bParts) {
				return fmt.Errorf("%w: %q is a prefix of %q", ErrOverlappingAuditPaths, a.Path, b.Path)
			}
			if isPathPrefix(bParts, aParts) {
				return fmt.Errorf("%w: %q is a prefix of %q", ErrOverlappingAuditPaths, b.Path, a.Path)
			}
		}
	}
	return nil
}

func isPathPrefix(short, long []string) bool {
	if len(short) >= len(long) {
		return false
	}
	for i, s := range short {
		if s != long[i] {
			return false
		}
	}
	return true
}
