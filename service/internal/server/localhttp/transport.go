// Package localhttp dispatches unary HTTP requests directly through an HTTP
// handler while preserving the normal Connect encoding and middleware stack.
package localhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"

	"connectrpc.com/connect"
)

const (
	maxHeaderBytes       = 1 << 20
	http2Major           = 2
	controlEntryOverhead = 32
)

var (
	errHandlerPanic       = errors.New("local HTTP handler panicked")
	errTransportClosed    = errors.New("local HTTP transport is closed")
	errHeadersTooLarge    = errors.New("local HTTP request headers exceed limit")
	errCompressedRequest  = errors.New("local HTTP transport does not support compressed request bodies")
	errCompressedResponse = errors.New("local HTTP transport does not support compressed response bodies")
)

// PanicInfo contains bounded server-side diagnostics for a recovered handler
// panic. It intentionally excludes the panic value and request headers so a
// panic cannot disclose a token or other request content through this hook.
type PanicInfo struct {
	Procedure string
	PanicType string
	Stack     []byte
}

// Transport dispatches requests through Handler without a socket. Each request
// receives a fresh server context: only cancellation and deadlines are bridged.
// Request metadata and tracing must cross as HTTP headers and be reconstructed
// by the handler's normal interceptors.
//
// Transport intentionally implements unary HTTP semantics only. It does not
// implement http.Flusher, Hijacker, or full-duplex response streaming.
type Transport struct {
	Handler      http.Handler
	PanicHandler func(PanicInfo)

	mu      sync.Mutex
	closing bool
	calls   map[*localCall]struct{}
}

// Client returns an HTTP client backed by the local transport. The small
// Connect-facing wrapper preserves v1's CodeInternal classification for a
// recovered handler panic without remapping unrelated transport failures.
func (t *Transport) Client() *http.Client {
	return &http.Client{Transport: connectCompatibilityRoundTripper{transport: t}}
}

type connectCompatibilityRoundTripper struct{ transport *Transport }

func (t connectCompatibilityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if errors.Is(err, errHandlerPanic) {
		return nil, connect.NewError(connect.CodeInternal, errHandlerPanic)
	}
	if resp != nil {
		resp.Body = &connectCompatibilityBody{ReadCloser: resp.Body}
	}
	return resp, err
}

type connectCompatibilityBody struct{ io.ReadCloser }

func (b *connectCompatibilityBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, errHandlerPanic) {
		err = connect.NewError(connect.CodeInternal, errHandlerPanic)
	}
	return n, err
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.Handler == nil {
		return nil, errors.New("local HTTP transport requires a handler")
	}
	if req == nil {
		return nil, errors.New("local HTTP transport requires a request")
	}
	if err := req.Context().Err(); err != nil {
		closeRequestBody(req.Body)
		return nil, err
	}
	if hasUnsupportedContentEncoding(req.Header) {
		closeRequestBody(req.Body)
		return nil, errCompressedRequest
	}
	if requestControlBytes(req) > maxHeaderBytes {
		closeRequestBody(req.Body)
		return nil, errHeadersTooLarge
	}

	serverCtx, cancel := bridgeContext(req.Context())
	call := newLocalCall(cancel, req.Body)
	if !t.addCall(call) {
		call.abort(errTransportClosed)
		return nil, errTransportClosed
	}
	serverReq := serverRequest(serverCtx, req)
	stopCancellation := context.AfterFunc(req.Context(), func() { call.abort(req.Context().Err()) })
	stopServerContext := context.AfterFunc(serverCtx, func() { call.abort(serverCtx.Err()) })

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.reportPanic(PanicInfo{
					Procedure: serverReq.URL.Path,
					PanicType: fmt.Sprintf("%T", recovered),
					Stack:     debug.Stack(),
				})
				call.writer.fail(errHandlerPanic)
			}
			call.closeRequest()
			call.writer.finish()
			stopCancellation()
			stopServerContext()
			cancel()
			t.removeCall(call)
			close(call.done)
		}()
		t.Handler.ServeHTTP(call.writer, serverReq)
	}()

	select {
	case <-call.writer.committed:
		if err := req.Context().Err(); err != nil {
			call.abort(err)
			return nil, err
		}
		if call.writer.hasUnsupportedContentEncoding() {
			call.abort(errCompressedResponse)
			return nil, errCompressedResponse
		}
		return call.writer.response(req, call), nil
	case err := <-call.writer.failed:
		call.abort(err)
		return nil, err
	case <-req.Context().Done():
		call.abort(req.Context().Err())
		return nil, req.Context().Err()
	}
}

// Shutdown rejects new calls and waits for active handlers to return without
// cancelling them. A handler that does not return cannot be forcibly
// terminated; in that case Shutdown returns the supplied context error while
// the handler remains active. Close provides force-cancellation of owned I/O.
func (t *Transport) Shutdown(ctx context.Context) error {
	calls := t.startClosing()
	for _, call := range calls {
		select {
		case <-call.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Close rejects new calls and cancels all currently owned I/O. It does not wait
// for arbitrary handler code to return; use Shutdown when draining is required.
func (t *Transport) Close() error {
	for _, call := range t.startClosing() {
		call.abort(errTransportClosed)
	}
	return nil
}

func (t *Transport) reportPanic(info PanicInfo) {
	if t.PanicHandler == nil {
		return
	}
	// Diagnostics must not change the transport failure contract, even if an
	// embedding logger hook itself panics.
	defer func() { _ = recover() }()
	t.PanicHandler(info)
}

func (t *Transport) addCall(call *localCall) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return false
	}
	if t.calls == nil {
		t.calls = make(map[*localCall]struct{})
	}
	t.calls[call] = struct{}{}
	return true
}

func (t *Transport) removeCall(call *localCall) {
	t.mu.Lock()
	delete(t.calls, call)
	t.mu.Unlock()
}

func (t *Transport) startClosing() []*localCall {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closing = true
	calls := make([]*localCall, 0, len(t.calls))
	for call := range t.calls {
		calls = append(calls, call)
	}
	return calls
}

func serverRequest(ctx context.Context, client *http.Request) *http.Request {
	serverURL := &url.URL{
		Path:       client.URL.Path,
		RawPath:    client.URL.RawPath,
		ForceQuery: client.URL.ForceQuery,
		RawQuery:   client.URL.RawQuery,
	}
	return (&http.Request{
		Method:        client.Method,
		URL:           serverURL,
		Proto:         "HTTP/2.0",
		ProtoMajor:    http2Major,
		ProtoMinor:    0,
		Header:        identityRequestHeaders(client.Header),
		Body:          client.Body,
		ContentLength: client.ContentLength,
		Host:          client.Host,
		Trailer:       client.Trailer.Clone(),
		RemoteAddr:    "local-http-ipc",
		RequestURI:    client.URL.RequestURI(),
	}).WithContext(ctx)
}

func identityRequestHeaders(headers http.Header) http.Header {
	serverHeaders := headers.Clone()
	serverHeaders.Del("Accept-Encoding")
	serverHeaders.Del("Connect-Accept-Encoding")
	return serverHeaders
}

func hasUnsupportedContentEncoding(headers http.Header) bool {
	for _, name := range []string{"Content-Encoding", "Connect-Content-Encoding"} {
		for _, value := range headers.Values(name) {
			for value != "" {
				encoding := value
				if comma := indexByte(value, ','); comma >= 0 {
					encoding, value = value[:comma], value[comma+1:]
				} else {
					value = ""
				}
				if encoding = trimSpace(encoding); encoding != "" && !strings.EqualFold(encoding, "identity") {
					return true
				}
			}
		}
	}
	return false
}

func bridgeContext(client context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := client.Deadline(); ok {
		return context.WithDeadline(context.Background(), deadline)
	}
	return context.WithCancel(context.Background())
}

func requestControlBytes(req *http.Request) int {
	total := len(req.Method) + len(req.Host) + len(req.URL.RequestURI())
	for _, header := range []http.Header{req.Header, req.Trailer} {
		for name, values := range header {
			total += len(name) + controlEntryOverhead // include map/slice control state
			for _, value := range values {
				total += len(value) + controlEntryOverhead
				if total > maxHeaderBytes {
					return total
				}
			}
		}
	}
	return total
}

func closeRequestBody(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}

type localCall struct {
	abortOnce        sync.Once
	requestCloseOnce sync.Once
	cancel           context.CancelFunc
	request          io.ReadCloser
	writer           *responseWriter
	done             chan struct{}
}

func newLocalCall(cancel context.CancelFunc, request io.ReadCloser) *localCall {
	call := &localCall{cancel: cancel, request: request, done: make(chan struct{})}
	call.writer = newResponseWriter()
	return call
}

func (c *localCall) closeRequest() {
	c.requestCloseOnce.Do(func() { closeRequestBody(c.request) })
}

func (c *localCall) abort(err error) {
	c.abortOnce.Do(func() {
		c.cancel()
		c.closeRequest()
		c.writer.fail(err)
		_ = c.writer.bodyReader.CloseWithError(err)
	})
}

type responseWriter struct {
	mu              sync.Mutex
	header          http.Header
	responseHeader  http.Header
	trailerSnapshot http.Header
	status          int
	preCommitFail   bool
	committed       chan struct{}
	failed          chan error
	commitOnce      sync.Once
	failOnce        sync.Once
	finishOnce      sync.Once
	bodyReader      *io.PipeReader
	bodyWriter      *io.PipeWriter
}

func newResponseWriter() *responseWriter {
	reader, writer := io.Pipe()
	return &responseWriter{
		header:     make(http.Header),
		committed:  make(chan struct{}),
		failed:     make(chan error, 1),
		bodyReader: reader,
		bodyWriter: writer,
	}
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(status int) {
	w.commitOnce.Do(func() {
		w.mu.Lock()
		w.status = status
		w.responseHeader = w.header.Clone()
		w.mu.Unlock()
		close(w.committed)
	})
}

func (w *responseWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.bodyWriter.Write(p)
}

func (w *responseWriter) fail(err error) {
	w.failOnce.Do(func() {
		w.mu.Lock()
		committed := w.status != 0
		w.preCommitFail = !committed
		w.mu.Unlock()
		if !committed {
			w.failed <- err
		}
		_ = w.bodyWriter.CloseWithError(err)
	})
}

func (w *responseWriter) finish() {
	w.finishOnce.Do(func() {
		w.mu.Lock()
		preCommitFail := w.preCommitFail
		w.mu.Unlock()
		if !preCommitFail {
			w.WriteHeader(http.StatusOK)
			w.mu.Lock()
			w.trailerSnapshot = w.header.Clone()
			w.mu.Unlock()
		}
		_ = w.bodyWriter.Close()
	})
}

func (w *responseWriter) hasUnsupportedContentEncoding() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return hasUnsupportedContentEncoding(w.responseHeader)
}

func (w *responseWriter) response(req *http.Request, call *localCall) *http.Response {
	w.mu.Lock()
	status := w.status
	header := w.responseHeader
	w.mu.Unlock()

	trailers := make(http.Header)
	for _, key := range header.Values("Trailer") {
		for _, name := range httpgutsHeaderValues(key) {
			trailers[name] = nil
		}
	}
	body := &responseBody{ReadCloser: w.bodyReader, call: call, writer: w, trailer: trailers}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/2.0",
		ProtoMajor:    http2Major,
		Header:        header,
		Body:          body,
		ContentLength: -1,
		Request:       req,
		Trailer:       trailers,
	}
}

func httpgutsHeaderValues(value string) []string {
	var names []string
	for value != "" {
		var name string
		if comma := indexByte(value, ','); comma >= 0 {
			name, value = value[:comma], value[comma+1:]
		} else {
			name, value = value, ""
		}
		name = http.CanonicalHeaderKey(trimSpace(name))
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func indexByte(value string, target byte) int {
	for i := range len(value) {
		if value[i] == target {
			return i
		}
	}
	return -1
}

func trimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

type responseBody struct {
	io.ReadCloser
	once    sync.Once
	call    *localCall
	writer  *responseWriter
	trailer http.Header
}

func (b *responseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.complete(err == io.EOF)
	}
	return n, err
}

func (b *responseBody) Close() error {
	err := b.ReadCloser.Close()
	b.complete(false)
	return err
}

func (b *responseBody) complete(copyTrailers bool) {
	b.once.Do(func() {
		if copyTrailers {
			b.writer.mu.Lock()
			snapshot := b.writer.trailerSnapshot
			for name := range b.trailer {
				b.trailer[name] = append([]string(nil), snapshot.Values(name)...)
			}
			b.writer.mu.Unlock()
		}
		b.call.abort(io.ErrClosedPipe)
	})
}
