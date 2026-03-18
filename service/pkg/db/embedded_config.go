package db

type EmbeddedConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// RootDir is an extension-owned runtime state directory.
	RootDir string `mapstructure:"root_dir" json:"root_dir"`
}
