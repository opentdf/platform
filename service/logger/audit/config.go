package audit

// JWTClaimMapping maps a JWT claim to a destination in the emitted audit log.
// The destination path uses dot notation over the audit log output shape, e.g.
// `eventMetaData.requester.sub`.
type JWTClaimMapping struct {
	Claim string `mapstructure:"claim" json:"claim"`
	Path  string `mapstructure:"path" json:"path"`
}

// Config contains platform-wide audit configuration.
type Config struct {
	// AuditedEntityJWTClaims is a legacy shorthand that writes stringified claim
	// values to `eventMetaData.entityMetadata.<claim>`.
	AuditedEntityJWTClaims []string `mapstructure:"audited_entity_jwt_claims" json:"audited_entity_jwt_claims"`
	// JWTClaimMappings writes JWT claims to configured destinations in the audit
	// log output, preserving the original JSON value types where possible.
	JWTClaimMappings []JWTClaimMapping `mapstructure:"jwt_claim_mappings" json:"jwt_claim_mappings"`
}
