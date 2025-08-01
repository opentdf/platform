package claims

// ClaimsConfig defines configuration for the JWT claims provider
type ClaimsConfig struct {
	// Description for this claims provider instance
	Description string `mapstructure:"description"`
}
