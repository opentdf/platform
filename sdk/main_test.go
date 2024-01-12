package sdk_test

import (
	"testing"

	"github.com/opentdf/opentdf-v2-poc/sdk"
	"github.com/stretchr/testify/assert"
)

func Test_NewClient_Returns_Error_When_Host_Is_Empty(t *testing.T) {
	_, err := sdk.NewClient("")

	assert.ErrorContains(t, err, "missing host")
}

// Test clients are created with a valid host
func Test_NewClient_Returns_Clients_When_Host_Is_Valid(t *testing.T) {
	clients, err := sdk.NewClient("localhost:8080")

	assert.Nil(t, err)
	assert.NotNil(t, clients)
	assert.NotNil(t, clients.ResourceEncodings)
	assert.NotNil(t, clients.SubjectEncodings)
	assert.NotNil(t, clients.Attributes)
	assert.NotNil(t, clients.KeyAccessGrants)
}
