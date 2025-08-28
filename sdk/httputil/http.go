package httputil

import (
	"crypto/tls"
	"net/http"
	"time"
)

const (
	defaultTimeout = 120 * time.Second
	// defaults to match DefaultTransport - defined to satisfy lint
	maxIdleConns          = 100
	idleConnTimeout       = 90 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	expectContinueTimeout = 1 * time.Second
)

var preventRedirectCheck = func(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse // Prevent following redirects
}

// SafeHTTPClient returns a default http client which has sensible timeouts, won't follow redirects, and enables idle
// connection pooling.
func SafeHTTPClient() *http.Client {
	return &http.Client{
		Transport:     http.DefaultTransport,
		Timeout:       defaultTimeout,
		CheckRedirect: preventRedirectCheck,
	}
}

// SafeHTTPClientWithTLSConfig returns a http client which has sensible timeouts, won't follow redirects, and if
// specified a http.Transport with the tls.Config provided.
func SafeHTTPClientWithTLSConfig(cfg *tls.Config) *http.Client {
	if cfg == nil {
		return SafeHTTPClient()
	}
	return SafeHTTPClientWithTransport(&http.Transport{
		TLSClientConfig: cfg,
		// config below matches DefaultTransport
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
	})
}

// SafeHTTPClientWithTransport returns a http client which has sensible timeouts, won't follow redirects, and if
// specified the provided http.Transport.
func SafeHTTPClientWithTransport(transport *http.Transport) *http.Client {
	if transport == nil {
		return SafeHTTPClient()
	}
	return &http.Client{
		Transport: transport,
		// config below matches our values for safeHttpClient
		Timeout:       defaultTimeout,
		CheckRedirect: preventRedirectCheck,
	}
}
