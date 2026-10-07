package cukes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWaitForPlatformRetriesUntilHealthy(t *testing.T) {
	var attempts atomic.Int32
	requests := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.String()
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// A service ready on the second probe must fit within a sub-second caller budget.
	ctx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancel()
	require.NoError(t, waitForPlatform(ctx, server.URL))
	require.EqualValues(t, 2, attempts.Load())
	require.Equal(t, "/healthz?service=all", <-requests)
	require.Equal(t, "/healthz?service=all", <-requests)
}

func TestWaitForPlatformHonorsDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, waitForPlatform(ctx, server.URL), context.DeadlineExceeded)
}

func TestWaitForPlatformCancelsPendingRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- waitForPlatform(ctx, server.URL)
	}()
	<-started
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
}
