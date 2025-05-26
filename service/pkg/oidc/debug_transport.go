package oidc

import (
	"log"
	"net/http"
	"net/http/httputil"
	"os"
)

// DebugTransport is an http.RoundTripper that logs requests and responses
type DebugTransport struct {
	Transport http.RoundTripper
	Logger    *log.Logger
}

// NewDebugTransport creates a new debug transport with a logger
func NewDebugTransport(transport http.RoundTripper) *DebugTransport {
	return &DebugTransport{
		Transport: transport,
		Logger:    log.New(os.Stderr, "[DEBUG_TRANSPORT] ", log.LstdFlags),
	}
}

// RoundTrip logs the request and response
func (t *DebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqData, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, err
	}

	// Log the URL and method
	t.Logger.Printf("REQUEST: %s %s\n", req.Method, req.URL.String())

	// Special handling for token exchange requests to log form data
	if req.Method == "POST" && req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		t.Logger.Printf("REQUEST FORM DATA: %s\n", string(reqData))
	}

	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respData, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return resp, nil
	}

	// Log response status and headers
	t.Logger.Printf("RESPONSE: %s - %d %s\n", req.URL.String(), resp.StatusCode, resp.Status)

	// For token exchange responses, log the full response
	if req.Method == "POST" && req.URL.Path == "/auth/realms/opentdf/protocol/openid-connect/token" {
		t.Logger.Printf("RESPONSE DATA: %s\n", string(respData))
	}

	return resp, nil
}
