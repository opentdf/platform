package sql

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestNewProviderUsesPGXForPostgres(t *testing.T) {
	config := DefaultConfig()
	config.Host = "127.0.0.1"
	config.Port = 0
	config.Database = "test"

	_, err := NewProvider(t.Context(), "postgres", config)
	require.Error(t, err)

	var parseError *pgconn.ParseConfigError
	require.ErrorAs(t, err, &parseError)
}
