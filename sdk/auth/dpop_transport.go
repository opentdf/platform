package auth

import (
	"bytes"
	"context"
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

// DPoPTransport wraps each go standard net/http RoundTripper request with DPoP (RFC 9449)
// proof tokens. These proofs are for both token endpoint (IdP, etc) calls and
// resource (i.e. KAS or policy service, for the SDK) endpoint calls,
// handling server-issued nonces with automatic retry.
type DPoPTransport struct {
	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// DPoPKey is the private key used to sign DPoP proofs.
	DPoPKey jwk.Key

	// TokenSource provides access tokens for resource requests.
	// For resource requests (any URL other than TokenEndpoint), the transport
	// sets Authorization: DPoP <token> and includes the ath claim binding the
	// proof to the access token. Requests to TokenEndpoint get neither.
	//
	// When TokenSource also implements AccessTokenCredentialSource and reports a
	// non-DPoP scheme for a resource request, the transport instead sets
	// Authorization: Bearer <token> and sends no DPoP proof, matching the
	// credential interceptor so a bearer token source is not forced onto DPoP.
	TokenSource AccessTokenSource

	// TokenEndpoint is the OAuth token endpoint URL.
	// Requests to this endpoint are treated as token requests
	// and do not include the ath claim.
	//
	// TokenEndpoint must not be mutated after the transport is first used:
	// isTokenEndpointRequest caches the parsed URL (and NewDPoPHTTPClient
	// pre-parses it at construction), so a later change would not take effect
	// and would race with the cached read.
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

var _ http.RoundTripper = (*DPoPTransport)(nil)

// RoundTrip implements http.RoundTripper, adding DPoP proofs to requests.
func (t *DPoPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.DPoPKey == nil {
		return nil, errors.New("DPoP transport has no signing key")
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	// NewDPoPHTTPClient initializes the cache; this Once covers a directly
	// constructed transport without paying a write-lock on every request.
	t.nonceOnce.Do(t.initNonceCache)

	// Avoid modifying the original
	req2 := cloneRequest(req)

	// Buffer the body and install GetBody on the clone so a DPoP-Nonce retry
	// can replay it. ConnectRPC/gRPC clients set Body and ContentLength but
	// not GetBody, so without this the retry path would send an empty body
	// against a non-zero ContentLength and net/http would abort the request.
	if err := bufferRequestBody(req2); err != nil {
		return nil, err
	}

	isTokenRequest := t.isTokenEndpointRequest(req2.URL)

	origin := getOrigin(req2.URL)
	nonce := t.getCachedNonce(origin)

	if err := t.addDPoPProof(req2, base, nonce, isTokenRequest); err != nil {
		return nil, fmt.Errorf("failed to add DPoP proof: %w", err)
	}

	resp, err := base.RoundTrip(req2)
	if err != nil {
		return resp, err
	}

	// Handle DPoP-Nonce challenge (RFC 9449 §8).
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

	// Handle DPoP-Nonce updates (RFC 9449 §8.2).
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
//
// For a resource request it first resolves the access token and its scheme. A
// bearer token source (one whose AccessTokenCredentialSource reports a non-DPoP
// scheme) short-circuits to Authorization: Bearer with no proof, mirroring the
// credential interceptor so it is not forced onto DPoP. Otherwise the proof is
// bound to the token via the ath claim and Authorization: DPoP is set.
func (t *DPoPTransport) addDPoPProof(req *http.Request, base http.RoundTripper, nonce string, isTokenRequest bool) error {
	// Resolve the resource-request credential up front so a bearer token source
	// short-circuits before any proof is built. Token-endpoint requests skip this:
	// they always carry a proof (no ath) regardless of the eventual token scheme.
	var credential AccessTokenCredential
	if !isTokenRequest && t.TokenSource != nil {
		var err error
		credential, err = t.resourceCredential(req.Context(), base)
		if err != nil {
			return fmt.Errorf("failed to get access token: %w", err)
		}
		if credential.Type != TokenTypeDPoP {
			// A bearer token is not sender-constrained: send no ath and no proof.
			// Drop any inherited DPoP header so a bearer request never carries a
			// stale proof on a retry clone.
			req.Header.Del("DPoP")
			req.Header.Set("Authorization", "Bearer "+string(credential.Token))
			return nil
		}
	}

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

	// For resource requests (not token endpoint), bind the proof to the access
	// token via the ath claim.
	accessToken := string(credential.Token)
	if !isTokenRequest && t.TokenSource != nil {
		// Calculate ath = base64url(SHA-256(access_token))
		h := sha256.New()
		h.Write([]byte(accessToken))
		ath := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		builder = builder.Claim("ath", ath)
	}

	token, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build DPoP token: %w", err)
	}

	publicKey, err := t.DPoPKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

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

	signedToken, err := jwt.Sign(token, jwt.WithKey(t.DPoPKey.Algorithm(), t.DPoPKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return fmt.Errorf("failed to sign DPoP token: %w", err)
	}

	req.Header.Set("DPoP", string(signedToken))

	// For resource requests, set Authorization header
	if !isTokenRequest && accessToken != "" {
		req.Header.Set("Authorization", "DPoP "+accessToken)
	}

	return nil
}

// resourceCredential resolves the access token and its authentication scheme for
// a resource request. When TokenSource implements AccessTokenCredentialSource the
// IdP-granted scheme is honored, so a bearer token source yields TokenTypeBearer.
// Otherwise the token is treated as DPoP sender-constrained, preserving the SDK's
// original transport behavior and matching the credential interceptor's default.
func (t *DPoPTransport) resourceCredential(ctx context.Context, base http.RoundTripper) (AccessTokenCredential, error) {
	client := &http.Client{Transport: base, Timeout: t.tokenFetchTimeout}
	if cs, ok := t.TokenSource.(AccessTokenCredentialSource); ok {
		return cs.AccessTokenCredential(ctx, client)
	}
	token, err := t.TokenSource.AccessToken(ctx, client)
	if err != nil {
		return AccessTokenCredential{}, err
	}
	return AccessTokenCredential{Token: token, Type: TokenTypeDPoP}, nil
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
// - Normalize an empty HTTP path to "/"
// - Strip query and fragment
//
// The path uses EscapedPath so percent-encoded reserved bytes (e.g. %2F) are
// preserved verbatim in the htu claim; u.Path would decode them and change the URI.
func normalizeURI(u *url.URL) string {
	escapedPath := u.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	return fmt.Sprintf("%s://%s%s", strings.ToLower(u.Scheme), normalizedHostPort(u), escapedPath)
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
// This transport is intended for bounded internal RPC request bodies. Go also
// treats ContentLength == 0 with a non-nil body as unknown, but such bodies are
// intentionally buffered to EOF here so nonce retries remain transparent.
// Callers must not pass an unbounded body in that form. ConnectRPC streaming
// requests use ContentLength < 0 and are left untouched, so they cannot be
// retried after a nonce challenge.
func bufferRequestBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength < 0 {
		return nil
	}
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
