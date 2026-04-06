package utils

import (
	"crypto/tls"
	"net/http"
)

func NewHTTPClient(tlsNoVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gosec // skip tls verification allowed if requested
				InsecureSkipVerify: tlsNoVerify,
			},
		},
	}
}
