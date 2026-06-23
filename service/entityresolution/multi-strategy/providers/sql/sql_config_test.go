package sql

import (
	"strings"
	"testing"
)

func TestDefaultConfigUsesPGXDriver(t *testing.T) {
	config := DefaultConfig()
	if config.Driver != defaultPostgreSQLDriver {
		t.Fatalf("expected default driver %q, got %q", defaultPostgreSQLDriver, config.Driver)
	}
}

func TestNormalizeDriverName(t *testing.T) {
	tests := []struct {
		name   string
		driver string
		want   string
	}{
		{
			name:   "pgx",
			driver: "pgx",
			want:   "pgx",
		},
		{
			name:   "postgres alias",
			driver: postgresDriverAlias,
			want:   "pgx",
		},
		{
			name:   "postgresql alias with whitespace and case",
			driver: " PostgreSQL ",
			want:   "pgx",
		},
		{
			name:   "other driver",
			driver: "sqlite3",
			want:   "sqlite3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDriverName(tt.driver); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestBuildConnectionStringSupportsPostgresAliases(t *testing.T) {
	tests := []string{"pgx", postgresDriverAlias, postgresQLDriverAlias, "Postgres"}

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
			if err != nil {
				t.Fatalf("expected postgres alias to build connection string: %v", err)
			}
			if !strings.Contains(connStr, "dbname=identity_db") {
				t.Fatalf("expected database name in connection string, got %q", connStr)
			}
		})
	}
}
