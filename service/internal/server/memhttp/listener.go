package memhttp

import (
	"context"
	"errors"
	"net"
	"sync"
)

type memoryListener struct {
	conns  chan net.Conn
	once   sync.Once
	closed chan struct{}
}

// Accept implements net.Listener.
func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

// Close implements net.Listener.
func (l *memoryListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

// Addr implements net.Listener.
func (l *memoryListener) Addr() net.Addr {
	return &memoryAddr{}
}

// DialContext is the type expected by http.Transport.DialContext.
func (l *memoryListener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	server, client := net.Pipe()
	select {
	case <-l.closed:
		return nil, errors.New("listener closed")
	case l.conns <- server:
		return client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type memoryAddr struct{}

// Network implements net.Addr.
func (*memoryAddr) Network() string { return "memory" }

// String implements io.Stringer, returning a value that matches the
// certificates used by net/http/httptest.
func (*memoryAddr) String() string { return "opentdf.io" }
