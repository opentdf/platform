package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIPCLifecycleServer(t *testing.T) *OpenTDFServer {
	t.Helper()
	otdf, err := NewOpenTDFServer(Config{
		Auth: auth.Config{Enabled: false},
		GRPC: GRPCConfig{
			MaxCallRecvMsgSizeBytes: 4 << 20,
			MaxCallSendMsgSizeBytes: 4 << 20,
		},
		Port:                    0,
		WellKnownConfigRegister: func(string, any) error { return nil },
	}, logger.CreateTestLogger(), nil)
	require.NoError(t, err)
	return otdf
}

func assertIPCConnectionsClosed(t *testing.T, otdf *OpenTDFServer, localConnURL string, localClient *http.Client) {
	t.Helper()

	localReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, localConnURL+"/after-stop", nil)
	require.NoError(t, err)
	localResp, err := localClient.Do(localReq)
	assert.Nil(t, localResp)
	require.ErrorContains(t, err, "local HTTP transport is closed")

	v1 := otdf.ConnectRPCInProcess.Conn()
	v1Req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, v1.Endpoint+"/after-stop", nil)
	require.NoError(t, err)
	v1Resp, err := v1.Client.Do(v1Req)
	if v1Resp != nil {
		_ = v1Resp.Body.Close()
	}
	require.Error(t, err, "the retained v1 in-process server must be closed")
}

func TestStopCleansLocalHTTPIPCBeforePublicServerStarts(t *testing.T) {
	otdf := newIPCLifecycleServer(t)
	conn := otdf.LocalHTTPIPCConnection()

	// This is the same path exercised by Start's deferred cleanup when a later
	// startup stage fails before the public listener is started.
	otdf.Stop()
	otdf.Stop() // cleanup is idempotent

	assertIPCConnectionsClosed(t, otdf, conn.Endpoint, conn.Client)
}

func TestStopContinuesAfterPublicShutdownTimeoutAndCooperativelyDrainsV2(t *testing.T) {
	otdf := newIPCLifecycleServer(t)
	otdf.shutdownTimeout = 100 * time.Millisecond

	publicEntered := make(chan struct{})
	publicRelease := make(chan struct{})
	publicDone := make(chan error, 1)
	otdf.HTTPMux.HandleFunc("/blocking-public", func(w http.ResponseWriter, _ *http.Request) {
		close(publicEntered)
		<-publicRelease
		_, _ = io.WriteString(w, "public complete")
	})

	v2Entered := make(chan struct{})
	v2Release := make(chan struct{})
	otdf.ConnectRPCInProcess.Mux.HandleFunc("/blocking-v2", func(w http.ResponseWriter, _ *http.Request) {
		close(v2Entered)
		<-v2Release
		_, _ = io.WriteString(w, "v2 drained")
	})
	localConn := otdf.LocalHTTPIPCConnection()

	require.NoError(t, otdf.Start())
	publicURL := "http://" + otdf.Listener.Addr().String() + "/blocking-public"
	go func() {
		resp, err := http.Get(publicURL)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		publicDone <- err
	}()
	<-publicEntered

	v2Done := make(chan struct {
		body string
		err  error
	}, 1)
	go func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, localConn.Endpoint+"/blocking-v2", nil)
		if err != nil {
			v2Done <- struct {
				body string
				err  error
			}{err: err}
			return
		}
		resp, err := localConn.Client.Do(req)
		var body []byte
		if resp != nil {
			body, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		v2Done <- struct {
			body string
			err  error
		}{body: string(body), err: err}
	}()
	<-v2Entered

	stopDone := make(chan struct{})
	go func() {
		otdf.Stop()
		close(stopDone)
	}()

	// A rejected new v2 call synchronizes with Stop having moved past the public
	// Shutdown deadline and begun the local cooperative drain.
	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, localConn.Endpoint+"/during-stop", nil)
		if err != nil {
			return false
		}
		resp, err := localConn.Client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err != nil && strings.Contains(err.Error(), "local HTTP transport is closed")
	}, time.Second, 5*time.Millisecond)
	close(v2Release)

	v2Result := <-v2Done
	require.NoError(t, v2Result.err)
	assert.Equal(t, "v2 drained", v2Result.body)
	<-stopDone
	assertIPCConnectionsClosed(t, otdf, localConn.Endpoint, localConn.Client)

	// net/http cannot forcibly terminate this arbitrary public handler. Releasing
	// it proves the timeout did not prevent owned IPC resources from closing.
	close(publicRelease)
	require.NoError(t, <-publicDone)
}

func TestStopBoundedForceCloseReleasesOwnedV2IO(t *testing.T) {
	otdf := newIPCLifecycleServer(t)
	otdf.shutdownTimeout = 50 * time.Millisecond

	v2Entered := make(chan struct{})
	handlerRelease := make(chan struct{})
	handlerDone := make(chan struct{})
	otdf.ConnectRPCInProcess.Mux.HandleFunc("/noncooperative-v2", func(http.ResponseWriter, *http.Request) {
		close(v2Entered)
		<-handlerRelease
		close(handlerDone)
	})
	localConn := otdf.LocalHTTPIPCConnection()
	callDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, localConn.Endpoint+"/noncooperative-v2", nil)
		if err != nil {
			callDone <- err
			return
		}
		resp, err := localConn.Client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		callDone <- err
	}()
	<-v2Entered

	stopDone := make(chan struct{})
	go func() {
		otdf.Stop()
		close(stopDone)
	}()
	<-stopDone

	require.ErrorContains(t, <-callDone, "local HTTP transport is closed")
	assertIPCConnectionsClosed(t, otdf, localConn.Endpoint, localConn.Client)
	select {
	case <-handlerDone:
		t.Fatal("force-closing owned I/O must not claim to terminate arbitrary handler code")
	default:
	}
	close(handlerRelease)
	<-handlerDone
}
