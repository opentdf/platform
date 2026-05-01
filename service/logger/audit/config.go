package audit

import "fmt"

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
	return nil
}
