package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_BuildConfig_ConnString(t *testing.T) {
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
		// Pool config should not pollute connection string
		{
			config: &Config{
				Host:     "myhost",
				Port:     1234,
				Database: "mydb",
				User:     "myuser",
				Password: "mypassword",
				SSLMode:  "require",
				Pool: PoolConfig{
					MinConns:          1,
					MaxConns:          10,
					MinIdleConns:      60,
					MaxConnLifetime:   3600,
					MaxConnIdleTime:   1800,
					HealthCheckPeriod: 60,
				},
			},
			want: "postgres://myuser:mypassword@myhost:1234/mydb?sslmode=require",
		},
	}

	for _, test := range tests {
		cfg, err := buildPostgresConfig(*test.config)
		require.NoError(t, err)
		assert.Equal(t, test.want, cfg.ConnString())
		// AfterConnect hook was defined when building
		assert.NotNil(t, cfg.AfterConnect)
	}
}
