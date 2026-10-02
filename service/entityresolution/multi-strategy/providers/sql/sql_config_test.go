package sql

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfigUsesPostgreSQLDriver(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, defaultPostgreSQLDriver, config.Driver)
}

func TestNormalizeDriverName(t *testing.T) {
	tests := []struct {
		name   string
		driver string
		want   string
	}{
		{
			name:   "pgx",
			driver: pgxDriverAlias,
			want:   canonicalPGXDriver,
		},
		{
			name:   "postgres default",
			driver: defaultPostgreSQLDriver,
			want:   canonicalPGXDriver,
		},
		{
			name:   "postgresql alias with whitespace and case",
			driver: " PostgreSQL ",
			want:   canonicalPGXDriver,
		},
		{
			name:   "other driver",
			driver: "mysql",
			want:   "mysql",
		},
		{
			name:   "sqlite driver",
			driver: "sqlite3",
			want:   "sqlite3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, normalizeDriverName(tt.driver))
		})
	}
}

func TestBuildConnectionStringSupportsPostgresAliases(t *testing.T) {
	tests := []string{canonicalPGXDriver, defaultPostgreSQLDriver, pgxDriverAlias, postgresQLDriverAlias, "Postgres"}

	for _, driver := range tests {
		t.Run(driver, func(t *testing.T) {
			provider := &Provider{
				config: Config{
					Driver:   driver,
					Host:     "localhost",
					Port:     5432,
					Database: "identity_db",
					Username: "ers_user",
					Password: "ers_password",
					SSLMode:  "require",
				},
			}

			connStr, err := provider.buildConnectionString()
			require.NoError(t, err)
			require.Contains(t, connStr, "dbname=identity_db")
		})
	}
}
