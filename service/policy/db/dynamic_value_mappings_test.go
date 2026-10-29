package db

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	servicedb "github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestCreateDynamicValueMappingRequiresNamespace(t *testing.T) {
	client := PolicyDBClient{}

	_, err := client.CreateDynamicValueMapping(t.Context(), &dynamicvaluemapping.CreateDynamicValueMappingRequest{})

	require.ErrorIs(t, err, servicedb.ErrMissingValue)
}
