package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pingOnlyPGX struct {
	PgxIface
	ping func(context.Context) error
}

func (p pingOnlyPGX) Ping(ctx context.Context) error {
	return p.ping(ctx)
}

func TestClientReadinessCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pingErr error
		wantErr error
	}{
		{
			name: "reachable database is ready",
		},
		{
			name:    "ping failure is not ready",
			pingErr: assert.AnError,
			wantErr: assert.AnError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := Client{Pgx: pingOnlyPGX{
				ping: func(context.Context) error { return test.pingErr },
			}}

			err := client.ReadinessCheck(time.Second)(t.Context())
			if test.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.wantErr)
			assert.ErrorContains(t, err, "database not ready")
		})
	}
}

func TestClientReadinessCheckTimesOutHungPing(t *testing.T) {
	t.Parallel()

	client := Client{Pgx: pingOnlyPGX{
		ping: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}}

	err := client.ReadinessCheck(time.Millisecond)(t.Context())
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func Test_BuildConfig_ConnString(t *testing.T) {
	tests := []struct {
		config            *Config
		want              string
		wantRuntimeParams map[string]string
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
		// Statement timeout should not be added as a runtime parameter unless configured.
		{
			config: &Config{
				Host:     "localhost",
				Port:     5432,
				Database: "opentdf",
				User:     "postgres",
				Password: "changeme",
				SSLMode:  "prefer",
			},
			want: "postgres://postgres:changeme@localhost:5432/opentdf?sslmode=prefer",
			wantRuntimeParams: map[string]string{
				"statement_timeout": "",
			},
		},
		{
			config: &Config{
				Host:             "localhost",
				Port:             5432,
				Database:         "opentdf",
				User:             "postgres",
				Password:         "changeme",
				SSLMode:          "prefer",
				StatementTimeout: 30,
			},
			want: "postgres://postgres:changeme@localhost:5432/opentdf?sslmode=prefer",
			wantRuntimeParams: map[string]string{
				"statement_timeout": "30s",
			},
		},
	}

	for _, test := range tests {
		cfg, err := test.config.buildConfig()
		require.NoError(t, err)
		assert.Equal(t, test.want, cfg.ConnString())
		// AfterConnect hook was defined when building
		assert.NotNil(t, cfg.AfterConnect)

		for key, value := range test.wantRuntimeParams {
			if value == "" {
				assert.NotContains(t, cfg.ConnConfig.RuntimeParams, key)
				continue
			}
			assert.Equal(t, value, cfg.ConnConfig.RuntimeParams[key])
		}
	}
}

func Test_BuildMigrationConfig_OverridesForMigration(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "disables statement timeout when statement timeout is configured",
			cfg: Config{
				Host:             "localhost",
				Port:             5432,
				Database:         "opentdf",
				User:             "postgres",
				Password:         "changeme",
				SSLMode:          "prefer",
				StatementTimeout: 30,
				Pool: PoolConfig{
					MaxConns:     10,
					MinConns:     2,
					MinIdleConns: 2,
				},
			},
		},
		{
			name: "disables statement timeout when statement timeout is not configured",
			cfg: Config{
				Host:     "localhost",
				Port:     5432,
				Database: "opentdf",
				User:     "postgres",
				Password: "changeme",
				SSLMode:  "prefer",
				Pool: PoolConfig{
					MaxConns:     10,
					MinConns:     2,
					MinIdleConns: 2,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := test.cfg.buildMigrationConfig()
			require.NoError(t, err)
			assert.Equal(t, "0", cfg.ConnConfig.RuntimeParams["statement_timeout"])
			assert.EqualValues(t, 1, cfg.MaxConns)
			assert.EqualValues(t, 0, cfg.MinConns)
			assert.EqualValues(t, 0, cfg.MinIdleConns)
		})
	}
}
