package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DPoPMode selects the htu form the DPoPTransport signs into proofs for resource
// requests. Token endpoint requests always use the RFC 9449 form.
type DPoPMode int

const (
	// DPoPModeRFC9449 always signs the full request URI (RFC 9449 §4.2). It is the
	// zero value, so a directly constructed transport keeps its original behavior.
	DPoPModeRFC9449 DPoPMode = iota
	// DPoPModeLegacy signs the bare Connect or gRPC procedure path
	// ("/package.Service/Method") for RPCs, as service releases before v0.18.0
	// require. Those releases reject a full-URL htu on RPCs.
	DPoPModeLegacy
	// DPoPModeAuto discovers per origin whether the server advertises RFC 9449
	// support, and uses the legacy form when it does not.
	DPoPModeAuto
)

func (m DPoPMode) String() string {
	switch m {
	case DPoPModeRFC9449:
		return "rfc9449"
	case DPoPModeLegacy:
		return "legacy"
	case DPoPModeAuto:
		return "auto"
	default:
		return fmt.Sprintf("DPoPMode(%d)", int(m))
	}
}

const (
	wellKnownConfigurationProcedure = "/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration"
	protectedResourceMetadataPath   = "/.well-known/oauth-protected-resource"
	dpopDiscoveryTimeout            = 10 * time.Second
	dpopDiscoveryMaxBody            = 1 << 20
	// dpopDiscoveryRetryInterval is how long an inconclusive discovery's legacy
	// fallback is reused before the origin is asked again.
	dpopDiscoveryRetryInterval = 30 * time.Second
)

// ServerSupportsRFC9449 reports whether an opentdf well-known configuration
// advertises RFC 9449 DPoP. A dpop block with a boolean rfc9449 field decides
// the answer. Otherwise a non-empty dpop_signing_alg_values_supported means
// support: every service release that publishes it (v0.18.0 and later) accepts
// full-URL htu. A false result does not rule out support advertised through
// RFC 9728 metadata.
func ServerSupportsRFC9449(cfg map[string]any) bool {
	if block, isMap := cfg["dpop"].(map[string]any); isMap {
		if supported, isBool := block["rfc9449"].(bool); isBool {
			return supported
		}
	}
	switch algs := cfg["dpop_signing_alg_values_supported"].(type) {
	case []any:
		return len(algs) > 0
	case []string:
		return len(algs) > 0
	default:
		return false
	}
}

// SetServerRFC9449Support records whether the server at serverURL accepts RFC 9449
// proofs, so DPoPModeAuto needn't discover it. Callers that have already fetched
// the server's well-known configuration can pass ServerSupportsRFC9449 of it.
// Only the origin (scheme, host and port) of serverURL is used, and the value
// replaces any discovered one. Recording false also skips the RFC 9728 check.
func (t *DPoPTransport) SetServerRFC9449Support(serverURL string, supported bool) error {
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("server URL %q needs a scheme and host", serverURL)
	}
	t.setOriginStyle(getOrigin(u), originStyle{rfc9449: supported})
	return nil
}

// originStyle is the cached htu form for one origin.
type originStyle struct {
	rfc9449 bool
	// retryAt is zero for a conclusive answer. Otherwise discovery was
	// inconclusive, and the origin is asked again once retryAt has passed.
	retryAt time.Time
}

func (s originStyle) inconclusive() bool { return !s.retryAt.IsZero() }

// setOriginStyle caches style for origin and returns the style it replaced.
func (t *DPoPTransport) setOriginStyle(origin string, style originStyle) originStyle {
	t.styleMu.Lock()
	defer t.styleMu.Unlock()
	if t.rfc9449ByOrigin == nil {
		t.rfc9449ByOrigin = make(map[string]originStyle)
	}
	previous := t.rfc9449ByOrigin[origin]
	t.rfc9449ByOrigin[origin] = style
	return previous
}

// useLegacyProof reports whether resource proofs for origin use the legacy htu.
// Mode values other than DPoPModeLegacy and DPoPModeAuto sign RFC 9449 proofs.
//
// In DPoPModeAuto the answer is discovered once per origin and cached, with
// concurrent first requests sharing one discovery. Discovery runs on the request
// path, bounded by dpopDiscoveryTimeout. An inconclusive discovery falls back to
// legacy for dpopDiscoveryRetryInterval. If ctx ends while waiting, its error is
// returned.
func (t *DPoPTransport) useLegacyProof(ctx context.Context, base http.RoundTripper, origin string) (bool, error) {
	switch t.Mode {
	case DPoPModeLegacy:
		return true, nil
	case DPoPModeAuto:
	case DPoPModeRFC9449:
		return false, nil
	default:
		return false, nil
	}

	t.styleMu.RLock()
	style, known := t.rfc9449ByOrigin[origin]
	t.styleMu.RUnlock()
	if known && (!style.inconclusive() || time.Now().Before(style.retryAt)) {
		return !style.rfc9449, nil
	}

	// The shared discovery must outlive any one caller's cancellation.
	discoveryCtx := context.WithoutCancel(ctx)
	results := t.discoveries.DoChan(origin, func() (any, error) {
		return t.discoverAndCache(discoveryCtx, base, origin), nil
	})
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case result := <-results:
		supported, _ := result.Val.(bool)
		return !supported, nil
	}
}

// discoverAndCache discovers origin's htu form, caches it, and logs a legacy
// answer once per origin (or once per run of inconclusive discoveries).
func (t *DPoPTransport) discoverAndCache(ctx context.Context, base http.RoundTripper, origin string) bool {
	d := discoverRFC9449(ctx, base, origin)
	style := originStyle{rfc9449: d.supported}
	if !d.conclusive {
		style.retryAt = time.Now().Add(dpopDiscoveryRetryInterval)
	}
	previous := t.setOriginStyle(origin, style)

	attrs := []any{
		slog.String("origin", origin),
		slog.Any("well_known_error", d.wellKnownErr),
		slog.Any("protected_resource_error", d.protectedResourceErr),
	}
	switch {
	case d.supported:
	case d.conclusive:
		slog.InfoContext(ctx, "server does not advertise RFC 9449 DPoP; using legacy proofs", attrs...)
	case previous.inconclusive():
		slog.DebugContext(ctx, "DPoP server discovery still failing; using legacy proofs", attrs...)
	default:
		slog.WarnContext(ctx, "DPoP server discovery failed; using legacy proofs until it is retried", attrs...)
	}
	return d.supported
}

// discovery is the outcome of asking an origin whether it accepts RFC 9449 proofs.
type discovery struct {
	supported bool
	// conclusive is false when the well-known configuration got no usable answer
	// (see errNoAnswer) and RFC 9728 metadata did not advertise support, so the
	// result should not be cached for long.
	conclusive           bool
	wellKnownErr         error
	protectedResourceErr error
}

// discoverRFC9449 asks the server at origin whether it accepts RFC 9449 proofs.
// It checks the opentdf well-known configuration, then RFC 9728 metadata if that
// doesn't advertise support. Neither request carries credentials or a proof: a
// client can't authenticate in a DPoP form it hasn't chosen yet.
func discoverRFC9449(ctx context.Context, base http.RoundTripper, origin string) discovery {
	ctx, cancel := context.WithTimeout(ctx, dpopDiscoveryTimeout)
	defer cancel()
	client := &http.Client{
		Transport: base,
		// A redirect is not the origin's own answer.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	var wellKnown struct {
		Configuration map[string]any `json:"configuration"`
	}
	wkErr := fetchDiscoveryJSON(ctx, client, http.MethodPost, origin+wellKnownConfigurationProcedure, &wellKnown)
	if wkErr == nil && ServerSupportsRFC9449(wellKnown.Configuration) {
		return discovery{supported: true, conclusive: true}
	}

	var metadata struct {
		AlgValues []string `json:"dpop_signing_alg_values_supported"`
	}
	prErr := fetchDiscoveryJSON(ctx, client, http.MethodGet, origin+protectedResourceMetadataPath, &metadata)
	if prErr == nil && len(metadata.AlgValues) > 0 {
		return discovery{supported: true, conclusive: true}
	}

	// RFC 9728 is new, so its absence says little. Only conclude "legacy" once
	// the well-known configuration itself has answered.
	return discovery{
		conclusive:           !errors.Is(wkErr, errNoAnswer),
		wellKnownErr:         wkErr,
		protectedResourceErr: prErr,
	}
}

// errNoAnswer marks a discovery failure that says nothing about the server's
// DPoP support: a network error, timeout, redirect, truncated body, or a status
// other than 200, 404, 405 and 501 (e.g. a gateway's 401 or 429, or a 5xx).
var errNoAnswer = errors.New("no answer")

func fetchDiscoveryJSON(ctx context.Context, client *http.Client, method, target string, into any) error {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Connect-Protocol-Version", "1")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoAnswer, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		// The server has no such endpoint.
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	default:
		return fmt.Errorf("%w: unexpected status %d", errNoAnswer, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, dpopDiscoveryMaxBody)).Decode(into); err != nil {
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
			// A 200 that isn't the expected JSON, such as a catch-all page, is a
			// definitive answer: the server serves no such document.
			return fmt.Errorf("decode %s: %w", target, err)
		}
		return fmt.Errorf("%w: decode %s: %w", errNoAnswer, target, err)
	}
	return nil
}

// legacyHTU returns the htu that service releases before v0.18.0 expect. For Connect and gRPC
// requests that is the procedure ("/package.Service/Method"), i.e. the last two
// path segments, which also drops any reverse-proxy path prefix. Other requests
// were always checked against the full URI, so they keep it.
func legacyHTU(req *http.Request) string {
	if !isConnectOrGRPC(req.Header) {
		return normalizeURI(req.URL)
	}
	segments := strings.Split(strings.Trim(req.URL.EscapedPath(), "/"), "/")
	if len(segments) < 2 { //nolint:mnd // a procedure is service and method
		return normalizeURI(req.URL)
	}
	return "/" + strings.Join(segments[len(segments)-2:], "/")
}

func isConnectOrGRPC(h http.Header) bool {
	if h.Get("Connect-Protocol-Version") != "" {
		return true
	}
	ct := h.Get("Content-Type")
	return strings.HasPrefix(ct, "application/grpc") || strings.HasPrefix(ct, "application/connect+")
}
