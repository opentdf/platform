package auth

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled     bool `yaml:"enabled" default:"true" `
	AuthNConfig `mapstructure:",squash"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct {
	Issuer            string   `yaml:"issuer" json:"issuer"`
	Audience          string   `yaml:"audience" json:"audience"`
	Clients           []string `yaml:"clients" json:"clients"`
	OIDCConfiguration `yaml:"-" json:"-"`
}
