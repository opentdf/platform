package localhttp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type contextKey string

func TestTransportUsesFreshContextAndHeaders(t *testing.T) {
	const key contextKey = "identity"
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Nil(t, req.Context().Value(key))
		assert.Equal(t, "serialized", req.Header.Get("X-Identity"))
		assert.NotEmpty(t, req.Header.Get("Traceparent"))
		_, _ = io.WriteString(w, "ok")
	})}

	req, err := http.NewRequestWithContext(context.WithValue(t.Context(), key, "caller-secret"), http.MethodPost, "http://local.test/action", strings.NewReader("request"))
	require.NoError(t, err)
	req.Header.Set("X-Identity", "serialized")
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "ok", string(body))
}

func TestTransportAbsentHeadersDoNotAppearFromContext(t *testing.T) {
	const key contextKey = "auth"
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Empty(t, req.Header.Get("Authorization"))
		assert.Nil(t, req.Context().Value(key))
		w.WriteHeader(http.StatusNoContent)
	})}
	req, err := http.NewRequestWithContext(context.WithValue(t.Context(), key, "context-only"), http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestTransportBridgesCancellationAndDeadline(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		seen := make(chan error, 1)
		entered := make(chan struct{})
		transport := &Transport{Handler: http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			close(entered)
			<-req.Context().Done()
			seen <- req.Context().Err()
		})}
		ctx, cancel := context.WithCancel(t.Context())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local.test/action", nil)
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() { _, err := transport.RoundTrip(req); done <- err }()
		<-entered
		cancel()
		require.ErrorIs(t, <-done, context.Canceled)
		require.ErrorIs(t, <-seen, context.Canceled)
	})

	t.Run("deadline", func(t *testing.T) {
		seen := make(chan time.Time, 1)
		transport := &Transport{Handler: http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			deadline, ok := req.Context().Deadline()
			assert.True(t, ok)
			seen <- deadline
			<-req.Context().Done()
		})}
		deadline := time.Now().Add(20 * time.Millisecond)
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local.test/action", nil)
		require.NoError(t, err)
		_, err = transport.RoundTrip(req)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.WithinDuration(t, deadline, <-seen, time.Millisecond)
	})
}

func TestTransportExplicitlyRejectsStreamingCapabilities(t *testing.T) {
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, flushSupported := w.(http.Flusher)
		assert.False(t, flushSupported)
		controller := http.NewResponseController(w)
		assert.ErrorIs(t, controller.EnableFullDuplex(), http.ErrNotSupported)
		w.WriteHeader(http.StatusNoContent)
	})}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://local.test/action", nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

func TestTransportResponseSemantics(t *testing.T) {
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Response", "value")
		w.Header().Set("Trailer", "X-Trailer")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "body")
		w.Header().Set("X-Trailer", "finished")
	})}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://local.test/action", nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "value", resp.Header.Get("X-Response"))
	assert.Equal(t, "body", string(body))
	assert.Equal(t, "finished", resp.Trailer.Get("X-Trailer"))
}

func TestTransportPanicFailureClasses(t *testing.T) {
	t.Run("before commitment", func(t *testing.T) {
		transport := &Transport{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("before") })}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		assert.Nil(t, resp)
		require.ErrorIs(t, err, errHandlerPanic)
	})

	t.Run("after commitment", func(t *testing.T) {
		transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "truncated")
			panic("after")
		})}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		assert.Equal(t, "truncated", string(body))
		require.ErrorIs(t, err, errHandlerPanic)
		require.NoError(t, resp.Body.Close())
	})
}

func TestTransportNestedAndConcurrentCalls(t *testing.T) {
	var transport *Transport
	var calls atomic.Int64
	transport = &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.Header.Get("X-Nested") == "" {
			nested, err := http.NewRequestWithContext(req.Context(), http.MethodGet, "http://local.test/nested", nil)
			assert.NoError(t, err)
			nested.Header.Set("X-Nested", "true")
			resp, err := transport.RoundTrip(nested)
			assert.NoError(t, err)
			_, err = io.Copy(io.Discard, resp.Body)
			assert.NoError(t, err)
			assert.NoError(t, resp.Body.Close())
		}
		_, _ = io.WriteString(w, "ok")
	})}

	const concurrency = 32
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/root", nil)
			if err == nil {
				var resp *http.Response
				resp, err = transport.RoundTrip(req)
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int64(concurrency*2), calls.Load())
}

func TestTransportCancelledBeforeDispatch(t *testing.T) {
	var calls atomic.Int64
	body := &trackingBody{Reader: strings.NewReader("body")}
	transport := &Transport{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local.test/action", body)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, calls.Load())
	assert.True(t, body.closed.Load())
}

func TestTransportCancellationUnblocksOwnedIO(t *testing.T) {
	started := make(chan struct{})
	writeErr := make(chan error, 1)
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		close(started)
		_, err := w.Write(make([]byte, 2<<20))
		writeErr <- err
	})}
	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	<-started
	cancel()
	select {
	case err := <-writeErr:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocked response write was not released by cancellation")
	}
	_, err = io.ReadAll(resp.Body)
	require.Error(t, err)
	_ = resp.Body.Close()
}

func TestTransportEarlyResponseCloseIsRaceSafe(t *testing.T) {
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Late")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 1000; i++ {
			w.Header().Set("X-Late", strings.Repeat("x", i%32))
			if _, err := w.Write([]byte("payload")); err != nil {
				return
			}
		}
	})}
	for range 100 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}
}

func TestServerRequestDoesNotInheritClientCapabilities(t *testing.T) {
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "HTTP/2.0", req.Proto)
		assert.Equal(t, 2, req.ProtoMajor)
		assert.Nil(t, req.TLS)
		assert.Nil(t, req.GetBody)
		assert.Empty(t, req.TransferEncoding)
		assert.False(t, req.Close)
		assert.Empty(t, req.URL.Scheme)
		assert.Empty(t, req.URL.Host)
		assert.Equal(t, "/action", req.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://local.test/action", strings.NewReader("body"))
	require.NoError(t, err)
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.0", 1, 0
	req.Close = true
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

func TestTransportEnforcesIdentityEncodingWithoutMutatingCaller(t *testing.T) {
	t.Run("offered response compression is removed", func(t *testing.T) {
		body := &trackingBody{Reader: strings.NewReader("caller-body")}
		transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Empty(t, req.Header.Get("Accept-Encoding"))
			assert.Empty(t, req.Header.Get("Connect-Accept-Encoding"))
			encoded, err := io.ReadAll(req.Body)
			assert.NoError(t, err)
			assert.Equal(t, "caller-body", string(encoded))
			_, _ = io.WriteString(w, "identity-response")
		})}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://local.test/action", body)
		require.NoError(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Connect-Accept-Encoding", "gzip")

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		responseBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "identity-response", string(responseBody))
		assert.Equal(t, "gzip", req.Header.Get("Accept-Encoding"))
		assert.Equal(t, "gzip", req.Header.Get("Connect-Accept-Encoding"))
		assert.Same(t, body, req.Body)
		assert.True(t, body.closed.Load())
	})

	t.Run("compressed request is rejected before dispatch", func(t *testing.T) {
		var calls atomic.Int64
		body := &trackingBody{Reader: strings.NewReader("compressed")}
		transport := &Transport{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://local.test/action", body)
		require.NoError(t, err)
		req.Header.Set("Content-Encoding", "gzip")

		resp, err := transport.RoundTrip(req)
		assert.Nil(t, resp)
		require.ErrorIs(t, err, errCompressedRequest)
		assert.Zero(t, calls.Load())
		assert.Equal(t, "gzip", req.Header.Get("Content-Encoding"))
		assert.Same(t, body, req.Body)
		assert.True(t, body.closed.Load())
	})

	t.Run("compressed response is rejected", func(t *testing.T) {
		transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "not-accepted")
		})}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		assert.Nil(t, resp)
		require.ErrorIs(t, err, errCompressedResponse)
	})
}

func TestTransportHeaderLimitAndLifecycle(t *testing.T) {
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	req.Header.Set("X-Large", strings.Repeat("x", maxHeaderBytes))
	resp, err := transport.RoundTrip(req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, errHeadersTooLarge)

	require.NoError(t, transport.Close())
	require.NoError(t, transport.Close())
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	resp, err = transport.RoundTrip(req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, errTransportClosed)
	require.NoError(t, transport.Shutdown(t.Context()))
}

func TestTransportShutdownDrainsExistingAndRejectsNewWork(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "drained")
	})}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	callBody := make(chan string, 1)
	callErr := make(chan error, 1)
	go func() {
		resp, err := transport.RoundTrip(req)
		if err == nil {
			var body []byte
			body, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			callBody <- string(body)
		}
		callErr <- err
	}()
	<-entered

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- transport.Shutdown(t.Context()) }()
	require.Eventually(t, func() bool {
		transport.mu.Lock()
		defer transport.mu.Unlock()
		return transport.closing
	}, time.Second, time.Millisecond)

	rejectedBody := &trackingBody{Reader: strings.NewReader("new")}
	rejected, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://local.test/action", rejectedBody)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(rejected)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, errTransportClosed)
	assert.True(t, rejectedBody.closed.Load())

	close(release)
	require.NoError(t, <-shutdownDone)
	require.NoError(t, <-callErr)
	assert.Equal(t, "drained", <-callBody)
}

func TestTransportShutdownTimeoutDoesNotCancelHandler(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		resp, err := transport.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, transport.Shutdown(ctx), context.DeadlineExceeded)
	select {
	case err := <-done:
		t.Fatalf("shutdown timeout terminated arbitrary handler: %v", err)
	default:
	}
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, transport.Shutdown(t.Context()))
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

type blockingBody struct {
	entered   chan struct{}
	released  chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
	closes    atomic.Int64
}

func newBlockingBody() *blockingBody {
	return &blockingBody{entered: make(chan struct{}), released: make(chan struct{})}
}

func (b *blockingBody) Read([]byte) (int, error) {
	b.enterOnce.Do(func() { close(b.entered) })
	<-b.released
	return 0, io.ErrClosedPipe
}

func (b *blockingBody) Close() error {
	b.closeOnce.Do(func() {
		b.closes.Add(1)
		close(b.released)
	})
	return nil
}

func TestTransportCancellationAndCloseUnblockRequestRead(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		trigger func(*Transport, context.CancelFunc)
		wantErr error
	}{
		{
			name:    "cancellation",
			context: func() (context.Context, context.CancelFunc) { return context.WithCancel(t.Context()) },
			trigger: func(_ *Transport, cancel context.CancelFunc) { cancel() },
			wantErr: context.Canceled,
		},
		{
			name: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(t.Context(), 20*time.Millisecond)
			},
			trigger: func(_ *Transport, _ context.CancelFunc) {},
			wantErr: context.DeadlineExceeded,
		},
		{
			name:    "transport close",
			context: func() (context.Context, context.CancelFunc) { return context.WithCancel(t.Context()) },
			trigger: func(transport *Transport, _ context.CancelFunc) { require.NoError(t, transport.Close()) },
			wantErr: errTransportClosed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			readErr := make(chan error, 1)
			transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, err := io.ReadAll(req.Body)
				readErr <- err
				w.WriteHeader(http.StatusNoContent)
			})}
			body := newBlockingBody()
			ctx, cancel := test.context()
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local.test/action", body)
			require.NoError(t, err)
			callDone := make(chan error, 1)
			go func() {
				resp, err := transport.RoundTrip(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				callDone <- err
			}()
			<-body.entered
			test.trigger(transport, cancel)
			require.ErrorIs(t, <-callDone, test.wantErr)
			require.ErrorIs(t, <-readErr, io.ErrClosedPipe)
			assert.Equal(t, int64(1), body.closes.Load(), "transport owns and closes the request body exactly once")
		})
	}
}

func TestTransportDoesNotReplay(t *testing.T) {
	var calls atomic.Int64
	transport := &Transport{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		panic("failed")
	})}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://local.test/action", nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.ReadAll(resp.Body)
	require.ErrorIs(t, err, errHandlerPanic)
	_ = resp.Body.Close()
	assert.Equal(t, int64(1), calls.Load())
}
