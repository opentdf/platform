package ldap

import (
	"crypto/tls"
	"errors"
)

// LDAP stubs for builds that don't want a real LDAP implementation.

type stubBackend struct{}

func NewStubBackend() Backend {
	return stubBackend{}
}

func (stubBackend) Dial(_, _ string) (Conn, error) {
	return nil, errors.New("LDAP not implemented - stub backend")
}

func (stubBackend) DialTLS(_, _ string, _ *tls.Config) (Conn, error) {
	return nil, errors.New("LDAP not implemented - stub backend")
}

func (stubBackend) EscapeFilter(filter string) string {
	return filter
}
