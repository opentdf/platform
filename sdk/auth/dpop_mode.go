package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	// DPoPModeLegacy signs the bare Connect procedure path, as the first OpenTDF
	// DPoP servers (service v0.11.x) require. Those servers reject a full-URL htu.
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
)

// ServerSupportsRFC9449 reports whether an opentdf well-known configuration
// advertises RFC 9449 DPoP. A dpop block, when present, is authoritative.
// Otherwise a non-empty dpop_signing_alg_values_supported means support: every
// service release that publishes it (v0.18.0 and later) accepts full-URL htu.
func ServerSupportsRFC9449(cfg map[string]any) bool {
	if block, ok := cfg["dpop"].(map[string]any); ok {
		supported, _ := block["rfc9449"].(bool)
		return supported
	}
	algs, _ := cfg["dpop_signing_alg_values_supported"].([]any)
	return len(algs) > 0
}

// discoverRFC9449 asks the server at origin whether it accepts RFC 9449 proofs,
// checking the opentdf well-known configuration and then RFC 9728 metadata.
// Both are fetched without credentials: a client can't authenticate in a DPoP
// form it hasn't chosen yet. definitive is false when neither source produced an
// HTTP answer from the well-known configuration, so the caller should not cache
// the result. It returns (supported, definitive).
func discoverRFC9449(ctx context.Context, base http.RoundTripper, origin string) (bool, bool) {
	ctx, cancel := context.WithTimeout(ctx, dpopDiscoveryTimeout)
	defer cancel()
	client := &http.Client{Transport: base}

	var wellKnown struct {
		Configuration map[string]any `json:"configuration"`
	}
	wkErr := fetchDiscoveryJSON(ctx, client, http.MethodPost, origin+wellKnownConfigurationProcedure, &wellKnown)
	if wkErr == nil && ServerSupportsRFC9449(wellKnown.Configuration) {
		return true, true
	}

	var metadata struct {
		AlgValues []string `json:"dpop_signing_alg_values_supported"`
	}
	prErr := fetchDiscoveryJSON(ctx, client, http.MethodGet, origin+protectedResourceMetadataPath, &metadata)
	if prErr == nil && len(metadata.AlgValues) > 0 {
		return true, true
	}

	// RFC 9728 is new, so its absence says little. Only cache "legacy" once the
	// well-known configuration itself has answered.
	if isTransportError(wkErr) {
		slog.WarnContext(ctx, "DPoP server discovery failed; using legacy proofs for this request",
			slog.String("origin", origin),
			slog.Any("well_known_error", wkErr),
			slog.Any("protected_resource_error", prErr),
		)
		return false, false
	}
	return false, true
}

// discoveryStatusError is an HTTP answer that isn't a usable document. Unlike a
// transport error it is definitive: the server responded and advertised nothing.
type discoveryStatusError struct{ status int }

func (e discoveryStatusError) Error() string {
	return fmt.Sprintf("unexpected status %d", e.status)
}

func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	_, isStatus := err.(discoveryStatusError) //nolint:errorlint // only produced unwrapped by fetchDiscoveryJSON
	return !isStatus
}

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
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("server error %d", resp.StatusCode) // transient: don't cache
	}
	if resp.StatusCode != http.StatusOK {
		return discoveryStatusError{status: resp.StatusCode}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, dpopDiscoveryMaxBody)).Decode(into); err != nil {
		// A 200 that isn't the expected JSON is still a definitive answer.
		return discoveryStatusError{status: resp.StatusCode}
	}
	return nil
}

// legacyHTU returns the htu a step-One server expects. For Connect and gRPC
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
