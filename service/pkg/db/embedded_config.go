package db

type EmbeddedConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// RootDir is the single mounted directory used by embedded Postgres.
	RootDir string `mapstructure:"root_dir" json:"root_dir"`
}
