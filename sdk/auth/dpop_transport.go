package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// DPoPTransport wraps an http.RoundTripper to add DPoP (RFC 9449) proof tokens
// to HTTP requests. It generates proofs for both token endpoint calls and
// resource endpoint calls, handling server-issued nonces with automatic retry.
type DPoPTransport struct {
	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// DPoPKey is the private key used to sign DPoP proofs.
	DPoPKey jwk.Key

	// TokenSource provides access tokens for resource requests.
	// When the token is DPoP-bound (token_type=DPoP), the transport
	// sets Authorization: DPoP <token> and includes the ath claim.
	TokenSource AccessTokenSource

	// TokenEndpoint is the OAuth token endpoint URL.
	// Requests to this endpoint are treated as token requests
	// and do not include the ath claim.
	TokenEndpoint string

	nonceMu           sync.RWMutex
	nonceCache        map[string]string
	cachedTokenURL    *url.URL
	cachedTokenURLStr string
}

// RoundTrip implements http.RoundTripper, adding DPoP proofs to requests.
func (t *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	t.nonceMu.Lock()
	if t.nonceCache == nil {
		t.nonceCache = make(map[string]string)
	}
	t.nonceMu.Unlock()

	// Clone request to avoid modifying the original
	req2 := cloneRequest(req)

	// Determine if this is a token endpoint request
	isTokenRequest := t.isTokenEndpointRequest(req2.URL)

	// Get cached nonce for this origin
	origin := getOrigin(req2.URL)
	nonce := t.getCachedNonce(origin)

	// Generate and add DPoP proof
	if err := t.addDPoPProof(req2, base, nonce, isTokenRequest); err != nil {
		return nil, fmt.Errorf("failed to add DPoP proof: %w", err)
	}

	// Make the request
	resp, err := base.RoundTrip(req2)
	if err != nil {
		return resp, err
	}

	// Handle DPoP-Nonce challenge (RFC 9449 §8)
	if resp.StatusCode == http.StatusUnauthorized {
		retryResp, retried, err := t.retryWithNonce(req, base, resp, origin, nonce, isTokenRequest)
		if err != nil {
			return nil, err
		}
		if retried {
			return retryResp, nil
		}
	}

	// Update cached nonce from successful responses
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if newNonce := resp.Header.Get("DPoP-Nonce"); newNonce != "" {
			t.setCachedNonce(origin, newNonce)
		}
	}

	return resp, nil
}

// retryWithNonce handles a DPoP-Nonce server challenge. It returns the retried
// response and true when a retry was performed, or the original response and
// false when no retry was needed (missing nonce header or nonce already used).
func (t *DPoPTransport) retryWithNonce(
	req *http.Request, base http.RoundTripper,
	resp *http.Response, origin, nonce string, isTokenRequest bool,
) (*http.Response, bool, error) {
	newNonce := resp.Header.Get("DPoP-Nonce")
	if newNonce == "" || nonce != "" {
		return resp, false, nil
	}

	t.setCachedNonce(origin, newNonce)
	resp.Body.Close()

	req3 := cloneRequest(req)
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, false, fmt.Errorf("failed to reset request body for retry: %w", err)
		}
		req3.Body = body
	}

	if err := t.addDPoPProof(req3, base, newNonce, isTokenRequest); err != nil {
		return nil, false, fmt.Errorf("failed to add DPoP proof with nonce: %w", err)
	}

	retryResp, err := base.RoundTrip(req3)
	return retryResp, true, err
}

// addDPoPProof generates and adds DPoP proof to the request headers.
func (t *DPoPTransport) addDPoPProof(req *http.Request, base http.RoundTripper, nonce string, isTokenRequest bool) error {
	// Normalize the htu (RFC 9449 HTTP URI Normalization)
	htu := normalizeURI(req.URL)

	// Build base proof claims
	builder := jwt.NewBuilder().
		Claim("jti", uuid.NewString()).
		Claim("htm", req.Method).
		Claim("htu", htu).
		IssuedAt(time.Now())

	// Add nonce if provided
	if nonce != "" {
		builder = builder.Claim("nonce", nonce)
	}

	// For resource requests (not token endpoint), add ath claim
	var accessToken string
	if !isTokenRequest && t.TokenSource != nil {
		client := &http.Client{Transport: base}
		at, err := t.TokenSource.AccessToken(req.Context(), client)
		if err != nil {
			return fmt.Errorf("failed to get access token: %w", err)
		}
		accessToken = string(at)

		// Calculate ath = base64url(SHA-256(access_token))
		h := sha256.New()
		h.Write([]byte(accessToken))
		ath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		builder = builder.Claim("ath", ath)
	}

	// Build the token
	token, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build DPoP token: %w", err)
	}

	// Get public key for jwk header
	publicKey, err := t.DPoPKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Create headers
	headers := jws.NewHeaders()
	if err := headers.Set(jws.JWKKey, publicKey); err != nil {
		return fmt.Errorf("failed to set jwk header: %w", err)
	}
	if err := headers.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		return fmt.Errorf("failed to set typ header: %w", err)
	}
	if err := headers.Set(jws.AlgorithmKey, t.DPoPKey.Algorithm()); err != nil {
		return fmt.Errorf("failed to set alg header: %w", err)
	}

	// Sign the token
	signedToken, err := jwt.Sign(token, jwt.WithKey(t.DPoPKey.Algorithm(), t.DPoPKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return fmt.Errorf("failed to sign DPoP token: %w", err)
	}

	// Add DPoP header
	req.Header.Set("DPoP", string(signedToken))

	// For resource requests, set Authorization header
	if !isTokenRequest && accessToken != "" {
		req.Header.Set("Authorization", "DPoP "+accessToken)
	}

	return nil
}

// isTokenEndpointRequest checks if the URL matches the configured token endpoint.
func (t *DPoPTransport) isTokenEndpointRequest(u *url.URL) bool {
	if t.TokenEndpoint == "" {
		return false
	}

	t.nonceMu.RLock()
	cachedURL := t.cachedTokenURL
	cachedStr := t.cachedTokenURLStr
	t.nonceMu.RUnlock()

	if cachedStr != t.TokenEndpoint {
		t.nonceMu.Lock()
		if t.cachedTokenURLStr != t.TokenEndpoint {
			parsed, err := url.Parse(t.TokenEndpoint)
			if err == nil {
				t.cachedTokenURL = parsed
				t.cachedTokenURLStr = t.TokenEndpoint
			} else {
				t.cachedTokenURL = nil
				t.cachedTokenURLStr = ""
			}
		}
		cachedURL = t.cachedTokenURL
		t.nonceMu.Unlock()
	}

	if cachedURL == nil {
		return false
	}

	return u.Scheme == cachedURL.Scheme &&
		u.Host == cachedURL.Host &&
		u.Path == cachedURL.Path
}

// normalizeURI normalizes the URI per RFC 9449 HTTP URI Normalization:
// - Lowercase scheme and host
// - Remove default ports (80 for http, 443 for https)
// - Strip query and fragment
func normalizeURI(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	// Remove default ports
	if (scheme == "http" && strings.HasSuffix(host, ":80")) ||
		(scheme == "https" && strings.HasSuffix(host, ":443")) {
		host = host[:strings.LastIndex(host, ":")]
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, u.Path)
}

// getOrigin returns the origin (scheme://host:port) from a URL, normalized to lowercase.
func getOrigin(u *url.URL) string {
	return strings.ToLower(fmt.Sprintf("%s://%s", u.Scheme, u.Host))
}

// getCachedNonce retrieves the cached nonce for an origin.
func (t *DPoPTransport) getCachedNonce(origin string) string {
	t.nonceMu.RLock()
	defer t.nonceMu.RUnlock()
	return t.nonceCache[origin]
}

// setCachedNonce stores a nonce for an origin.
func (t *DPoPTransport) setCachedNonce(origin, nonce string) {
	t.nonceMu.Lock()
	defer t.nonceMu.Unlock()
	t.nonceCache[origin] = nonce
}

// cloneRequest creates a shallow clone of the request.
func cloneRequest(req *http.Request) *http.Request {
	req2 := req.Clone(req.Context())
	// Clone headers to avoid modifying the original
	req2.Header = req.Header.Clone()
	return req2
}

// NewDPoPHTTPClient creates a new HTTP client with DPoP transport wrapping.
// The client will automatically add DPoP proofs to all requests.
func NewDPoPHTTPClient(baseClient *http.Client, dpopKey jwk.Key, tokenSource AccessTokenSource, tokenEndpoint string) *http.Client {
	if baseClient == nil {
		baseClient = http.DefaultClient
	}

	transport := baseClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	dpopTransport := &DPoPTransport{
		Base:          transport,
		DPoPKey:       dpopKey,
		TokenSource:   tokenSource,
		TokenEndpoint: tokenEndpoint,
	}

	return &http.Client{
		Transport:     dpopTransport,
		CheckRedirect: baseClient.CheckRedirect,
		Jar:           baseClient.Jar,
		Timeout:       baseClient.Timeout,
	}
}
