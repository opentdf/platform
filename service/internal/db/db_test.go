package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_BuildConfig(t *testing.T) {
	tests := []struct {
		config *Config
		want   string
	}{
		{
			config: &Config{
				Host:     "localhost",
				Port:     5432,
				Database: "opentdf",
				User:     "postgres",
				Password: "changeme",
			},
			want: "postgres://postgres:changeme@localhost:5432/opentdf?sslmode=",
		},
		{
			config: &Config{
				Host:     "localhost",
				Port:     5432,
				Database: "opentdf",
				User:     "postgres",
				Password: "tes}t64@N0test;/-test/-z",
			},
			want: "postgres://postgres:tes%7Dt64%40N0test%3B%2F-test%2F-z@localhost:5432/opentdf?sslmode=",
		},
		{
			config: &Config{
				Host:     "localhost",
				Port:     5432,
				Database: "opentdf",
				User:     "postgres",
				Password: "k!jBwK@$gn@M!ikpHo8SZ8",
				SSLMode:  "prefer",
			},
			want: "postgres://postgres:k%21jBwK%40%24gn%40M%21ikpHo8SZ8@localhost:5432/opentdf?sslmode=prefer",
		},
	}

	for _, test := range tests {
		cfg, err := test.config.buildConfig()
		require.NoError(t, err)
		assert.Equal(t, test.want, cfg.ConnString())
	}
}
