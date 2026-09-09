package server

import (
	"net/http"
	"testing"

	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopCleansLocalHTTPIPCBeforePublicServerStarts(t *testing.T) {
	otdf, err := NewOpenTDFServer(Config{
		Auth: auth.Config{Enabled: false},
		GRPC: GRPCConfig{
			MaxCallRecvMsgSizeBytes: 4 << 20,
			MaxCallSendMsgSizeBytes: 4 << 20,
		},
		WellKnownConfigRegister: func(string, any) error { return nil },
	}, logger.CreateTestLogger(), nil)
	require.NoError(t, err)
	conn := otdf.LocalHTTPIPCConnection()

	// This is the same path exercised by Start's deferred cleanup when a later
	// startup stage fails before the public listener is started.
	otdf.Stop()
	otdf.Stop() // cleanup is idempotent

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, conn.Endpoint+"/not-dispatched", nil)
	require.NoError(t, err)
	resp, err := conn.Client.Do(req)
	assert.Nil(t, resp)
	require.Error(t, err)
	require.ErrorContains(t, err, "local HTTP transport is closed")
}
