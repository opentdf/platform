package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	// For resource requests (any URL other than TokenEndpoint), the transport
	// sets Authorization: DPoP <token> and includes the ath claim binding the
	// proof to the access token. Requests to TokenEndpoint get neither.
	TokenSource AccessTokenSource

	// TokenEndpoint is the OAuth token endpoint URL.
	// Requests to this endpoint are treated as token requests
	// and do not include the ath claim.
	TokenEndpoint string

	// tokenFetchTimeout bounds the internal access-token fetch performed while
	// adding the ath claim to resource requests. It mirrors the configured
	// client's Timeout so a hung IdP cannot stall the request indefinitely.
	tokenFetchTimeout time.Duration

	nonceOnce         sync.Once
	nonceMu           sync.RWMutex
	nonceCache        map[string]string
	cachedTokenURL    *url.URL
	cachedTokenURLStr string
}

// RoundTrip implements http.RoundTripper, adding DPoP proofs to requests.
func (t *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Guard the zero value / direct construction: addDPoPProof dereferences the key
	// unconditionally, so a nil key would otherwise nil-panic mid-request.
	if t.DPoPKey == nil {
		return nil, errors.New("DPoP transport has no signing key")
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	// NewDPoPHTTPClient initializes the cache; the Once covers a directly
	// constructed transport without paying a write-lock on every request.
	t.nonceOnce.Do(t.initNonceCache)

	// Clone request to avoid modifying the original
	req2 := cloneRequest(req)

	// Buffer the body and install GetBody on the clone so a DPoP-Nonce retry
	// can replay it. ConnectRPC/gRPC clients set Body and ContentLength but
	// not GetBody, so without this the retry path would send an empty body
	// against a non-zero ContentLength and net/http would abort the request.
	if err := bufferRequestBody(req2); err != nil {
		return nil, err
	}

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

	// Handle DPoP-Nonce challenge (RFC 9449 §8). Resource servers signal a required
	// nonce with 401, while the authorization server (token endpoint) uses 400; handle
	// both. On a retry, fall through with the retried response so its own DPoP-Nonce (if
	// the server rotates the nonce on the now-successful response) still updates the
	// cache below; returning early here would drop it and force another challenge on the
	// next request.
	if resp.StatusCode == http.StatusUnauthorized ||
		(resp.StatusCode == http.StatusBadRequest && resp.Header.Get("DPoP-Nonce") != "") {
		retryResp, retried, err := t.retryWithNonce(req2, base, resp, origin, nonce, isTokenRequest)
		if err != nil {
			return nil, err
		}
		if retried {
			resp = retryResp
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
// false when no retry was needed.
//
// A retry happens once per request whenever the server supplies a DPoP-Nonce
// that differs from the one we already sent (RFC 9449 §8). Requiring a *different*
// nonce both covers the initial challenge (we sent none) and a server that rotates
// its nonce after previously accepting one, while preventing a retry loop when the
// server keeps returning the same nonce we just used. The single retry is returned
// as-is even if it is itself a 401.
func (t *DPoPTransport) retryWithNonce(
	req *http.Request, base http.RoundTripper,
	resp *http.Response, origin, nonce string, isTokenRequest bool,
) (*http.Response, bool, error) {
	newNonce := resp.Header.Get("DPoP-Nonce")
	if newNonce == "" || newNonce == nonce {
		return resp, false, nil
	}

	t.setCachedNonce(origin, newNonce)

	// A one-shot body (streaming / unknown length) was consumed by the first
	// attempt and cannot be replayed; cache the nonce for the next request but
	// return the 401 rather than resending an empty body.
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, false, nil
	}

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
		client := &http.Client{Transport: base, Timeout: t.tokenFetchTimeout}
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

	return normalizeURI(u) == normalizeURI(cachedURL)
}

// normalizedHostPort returns the URL host lowercased with the scheme's default
// port (80 for http, 443 for https) removed. IPv6 literals keep their brackets.
func normalizedHostPort(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // re-bracket IPv6 literal stripped by Hostname()
	}

	port := u.Port()
	if port == "" ||
		(scheme == "http" && port == "80") ||
		(scheme == "https" && port == "443") {
		return host
	}

	return host + ":" + port
}

// normalizeURI normalizes the URI per RFC 9449 HTTP URI Normalization:
// - Lowercase scheme and host
// - Remove default ports (80 for http, 443 for https)
// - Strip query and fragment
//
// The path uses EscapedPath so percent-encoded reserved bytes (e.g. %2F) are
// preserved verbatim in the htu claim; u.Path would decode them and change the URI.
func normalizeURI(u *url.URL) string {
	return fmt.Sprintf("%s://%s%s", strings.ToLower(u.Scheme), normalizedHostPort(u), u.EscapedPath())
}

// getOrigin returns the origin (scheme://host:port) from a URL, normalized to
// lowercase with the scheme's default port removed.
func getOrigin(u *url.URL) string {
	return fmt.Sprintf("%s://%s", strings.ToLower(u.Scheme), normalizedHostPort(u))
}

// initNonceCache lazily allocates the per-origin nonce cache. It is idempotent
// and safe to call once via nonceOnce even when the constructor already set it.
func (t *DPoPTransport) initNonceCache() {
	t.nonceMu.Lock()
	defer t.nonceMu.Unlock()
	if t.nonceCache == nil {
		t.nonceCache = make(map[string]string)
	}
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

// bufferRequestBody reads req.Body into SDK-owned memory and replaces both Body
// and GetBody on req so the body can be replayed safely on retry.
//
// We buffer even when the caller already set GetBody (which ConnectRPC does for
// unary calls). ConnectRPC's GetBody hands back a single shared *payloadCloser
// with a mutable read offset; when net/http reuses a keep-alive connection that
// the server has since closed (the auth interceptor returns the 401 DPoP-Nonce
// challenge without draining the body), net/http's internal rewind-and-retry
// races on that shared offset and can present an empty body, surfacing as
// "ContentLength=N with Body length 0". Replacing GetBody with a factory that
// returns an independent bytes.Reader over an immutable []byte removes the
// shared mutable state, so every (re)send reads the full payload.
//
// Streaming/unknown-length requests (ContentLength < 0, e.g. ConnectRPC client
// streams over an io.Pipe) are left untouched so the stream is not drained;
// DPoP-nonce retry is only meaningful for unary calls anyway.
func bufferRequestBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength < 0 {
		return nil
	}
	// Pre-size from ContentLength (guaranteed >= 0 here) so this is a single exact
	// allocation instead of io.ReadAll's grow-by-doubling. ConnectRPC unary payloads
	// are already fully buffered in memory, so this is a straight copy of a
	// known-length body. ReadFrom still reads to EOF, so behavior is unchanged if
	// ContentLength ever under-/over-states the actual body.
	buf := bytes.NewBuffer(make([]byte, 0, req.ContentLength))
	_, readErr := buf.ReadFrom(req.Body)
	closeErr := req.Body.Close()
	if readErr != nil {
		return fmt.Errorf("buffering DPoP request body: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing DPoP request body: %w", closeErr)
	}
	data := buf.Bytes()
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return nil
}

// NewDPoPHTTPClient creates a new HTTP client with DPoP transport wrapping.
// The client will automatically add DPoP proofs to all requests.
//
// It returns an error when tokenEndpoint is non-empty but cannot be parsed: an
// unparseable endpoint would otherwise make token-endpoint requests silently
// misclassified as resource requests (adding an ath claim and Authorization
// header to the token exchange itself).
func NewDPoPHTTPClient(baseClient *http.Client, dpopKey jwk.Key, tokenSource AccessTokenSource, tokenEndpoint string) (*http.Client, error) {
	if baseClient == nil {
		baseClient = http.DefaultClient
	}

	transport := baseClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	dpopTransport := &DPoPTransport{
		Base:              transport,
		DPoPKey:           dpopKey,
		TokenSource:       tokenSource,
		TokenEndpoint:     tokenEndpoint,
		tokenFetchTimeout: baseClient.Timeout,
		nonceCache:        make(map[string]string),
	}

	// Validate and cache the parsed endpoint up front so isTokenEndpointRequest
	// never has to swallow a parse error at request time.
	if tokenEndpoint != "" {
		parsed, err := url.Parse(tokenEndpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid DPoP token endpoint %q: %w", tokenEndpoint, err)
		}
		dpopTransport.cachedTokenURL = parsed
		dpopTransport.cachedTokenURLStr = tokenEndpoint
	}

	return &http.Client{
		Transport:     dpopTransport,
		CheckRedirect: baseClient.CheckRedirect,
		Jar:           baseClient.Jar,
		Timeout:       baseClient.Timeout,
	}, nil
}
