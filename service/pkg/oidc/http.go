package oidc

import (
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type httpClient struct {
	httpClient *http.Client
	dpopJWK    jwk.Key
}

func NewHTTPClient(client *http.Client, dpopJWK jwk.Key) (*httpClient, error) {
	if client == nil {
		client = &http.Client{}
	}

	if dpopJWK == nil {
		var err error
		dpopJWK, err = GenerateDPoPKey() // Generate a new DPoP key if not provided
		if err != nil {
			return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
		}
	}

	return &httpClient{
		httpClient: client,
		dpopJWK:    dpopJWK,
	}, nil
}

// DoWithDPoP executes a request with DPoP, handling nonce retries. It takes a factory to create a new request for each attempt.
func (c *httpClient) DoWithDPoP(reqFactory func(nonce string) (*http.Request, error), endpoint string) (*http.Response, error) {
	req, err := reqFactory("")
	if err != nil {
		return nil, err
	}
	if err := AttachDPoPHeader(req, c.dpopJWK, endpoint, ""); err != nil {
		return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == 400 {
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce != "" {
			resp.Body.Close()
			req, err := reqFactory(nonce)
			if err != nil {
				return nil, err
			}
			if err := AttachDPoPHeader(req, c.dpopJWK, endpoint, nonce); err != nil {
				return nil, fmt.Errorf("failed to attach DPoP header: %w", err)
			}
			return c.httpClient.Do(req)
		}
	}
	return resp, err
}
