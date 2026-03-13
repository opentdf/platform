package db

type EmbeddedConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// RootDir is the single mounted directory used by embedded Postgres.
	RootDir string `mapstructure:"root_dir" json:"root_dir"`
	// StartTimeoutSeconds configures how long to wait for embedded Postgres to start.
	StartTimeoutSeconds int `mapstructure:"start_timeout_seconds" json:"start_timeout_seconds" default:"30"`
	// StopTimeoutSeconds configures how long to wait for embedded Postgres to stop.
	StopTimeoutSeconds int `mapstructure:"stop_timeout_seconds" json:"stop_timeout_seconds" default:"10"`
}
