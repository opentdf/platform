// Package memhttp provides an in-memory HTTP server and client. For
// testing-specific adapters, see the memhttptest subpackage.
package memhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server is a net/http server that uses in-memory pipes instead of TCP. By
// default, it has TLS enabled and supports HTTP/2. It otherwise uses the same
// configuration as the zero value of [http.Server].
type Server struct {
	server         *http.Server
	Listener       *memoryListener
	url            string
	serveErr       chan error
	cleanupContext func() (context.Context, context.CancelFunc)
}

// New constructs and starts a Server.
func New(handler http.Handler, opts ...Option) *Server {
	var cfg config
	WithCleanupTimeout(5 * time.Second).apply(&cfg) //nolint:mnd // Specific to cleanup timeout.
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	mlis := &memoryListener{
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}

	var lis net.Listener = mlis

	http2Server := &http2.Server{}

	handler = h2c.NewHandler(handler, http2Server)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, //nolint:mnd // Specific to read header timeout.
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(lis)
	}()

	return &Server{
		server:         server,
		Listener:       mlis,
		url:            fmt.Sprintf("http://%s", mlis.Addr().String()),
		serveErr:       serveErr,
		cleanupContext: cfg.CleanupContext,
	}
}

// Transport returns an [http2.Transport] configured to use in-memory pipes
// rather than TCP, disable automatic compression, trust the server's TLS
// certificate (if any), and use HTTP/2 (if the server supports it).
//
// Callers may reconfigure the returned Transport without affecting other
// transports or clients.
func (s *Server) Transport() *http2.Transport {
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return s.Listener.DialContext(ctx, network, addr)
		},
		AllowHTTP: true,
	}

	return transport
}

// Client returns an [http.Client] configured to use in-memory pipes rather
// than TCP, disable automatic compression, trust the server's TLS certificate
// (if any), and use HTTP/2 (if the server supports it).
//
// Callers may reconfigure the returned client without affecting other clients.
func (s *Server) Client() *http.Client {
	return &http.Client{Transport: s.Transport()}
}

// URL returns the server's URL.
func (s *Server) URL() string {
	return s.url
}

// Close immediately shuts down the server. To shut down the server without
// interrupting in-flight requests, use Shutdown.
func (s *Server) Close() error {
	if err := s.server.Close(); err != nil {
		return err
	}
	return s.listenErr()
}

// Shutdown gracefully shuts down the server, without interrupting any active
// connections. See [http.Server.Shutdown] for details.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.server.Shutdown(ctx); err != nil {
		return err
	}
	return s.listenErr()
}

// Cleanup calls Shutdown with a five second timeout. To customize the timeout,
// use WithCleanupTimeout.
//
// Cleanup is primarily intended for use in tests. If you find yourself using
// it, you may want to use the memhttptest package instead.
func (s *Server) Cleanup() error {
	ctx, cancel := s.cleanupContext()
	defer cancel()
	return s.Shutdown(ctx)
}

// RegisterOnShutdown registers a function to call on Shutdown. It's often used
// to cleanly shut down connections that have been hijacked. See
// [http.Server.RegisterOnShutdown] for details.
func (s *Server) RegisterOnShutdown(f func()) {
	s.server.RegisterOnShutdown(f)
}

func (s *Server) listenErr() error {
	if err := <-s.serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
