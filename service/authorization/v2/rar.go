// Package authorization adds an RFC 8693 token-exchange endpoint that issues
// access tokens carrying RFC 9396 authorization_details claims. The endpoint
// is a thin "token decoration" layer: it does NOT implement a full OAuth 2.0
// Authorization Server — no /authorize, no PKCE, no refresh tokens, no client
// registration. The caller MUST present a subject token verified by the
// platform's existing token verifier (i.e. an IdP-issued JWT).
//
// Flow per request:
//
//  1. Parse RFC 8693 form parameters (grant_type, subject_token,
//     subject_token_type, requested_token_type, authorization_details).
//  2. Verify subject_token using the configured AccessTokenVerifier.
//  3. For each authorization_details entry, fan out to the existing v2 PDP.
//     Only (action, location) combinations the PDP permits make it into the
//     issued token.
//  4. Mint and sign a JWT with the granted authorization_details, return as
//     application/json per RFC 8693 §2.2.
//
// The issuer's signing key is ephemeral by default — restarting the process
// invalidates outstanding tokens. The public JWKS is exposed at the companion
// endpoint so resource servers can verify.
package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	authn "github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

// IANA-registered URIs from RFC 8693 — these are public identifiers, not
// credentials, but gosec G101 keyword-matches "token" / "grant-type" and
// flags them, hence the per-line nolint annotations below.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 IANA URI

	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          //nolint:gosec // RFC 8693 IANA URI
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // RFC 8693 IANA URI
	tokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"     //nolint:gosec // RFC 8693 IANA URI

	// Custom RAR detail type understood by this POC. Other type values cause
	// the detail to be rejected at validation time.
	detailTypeOpenTDFAttribute = "opentdf_attribute"

	rarTokenPath = "/v2/authorization/token"
	rarJWKSPath  = "/v2/authorization/jwks.json"
)

// AuthorizationDetail mirrors the RFC 9396 object. Only the fields meaningful
// to the POC are typed; unknown keys round-trip via UnknownFields so policy
// authors can add metadata without us silently dropping it.
type AuthorizationDetail struct {
	Type          string         `json:"type"`
	Actions       []string       `json:"actions,omitempty"`
	Locations     []string       `json:"locations,omitempty"`
	Datatypes     []string       `json:"datatypes,omitempty"`
	Identifier    string         `json:"identifier,omitempty"`
	Privileges    []string       `json:"privileges,omitempty"`
	UnknownFields map[string]any `json:"-"`
}

// tokenExchangeResponse follows RFC 8693 §2.2.
type tokenExchangeResponse struct {
	AccessToken          string                `json:"access_token"`
	IssuedTokenType      string                `json:"issued_token_type"`
	TokenType            string                `json:"token_type"`
	ExpiresIn            int64                 `json:"expires_in"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
}

// rarErrorResponse follows RFC 6749 §5.2.
type rarErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RAREndpoint owns the dependencies for the token issuance flow. The PDP
// dependency is the same Service that hosts GetDecision*, so policy reuse is
// implicit — no second copy of the entitlement store.
type RAREndpoint struct {
	pdp      *Service
	signer   *RARSigner
	verifier authn.AccessTokenVerifier
}

// Mount attaches the RAR token + JWKS handlers to the supplied mux.
func (r *RAREndpoint) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST "+rarTokenPath, r.handleToken)
	mux.HandleFunc("GET "+rarJWKSPath, r.handleJWKS)
}

func (r *RAREndpoint) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	if r.signer == nil {
		writeError(w, http.StatusServiceUnavailable, "server_error", "rar signer not configured")
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(r.signer.JWKS()); err != nil {
		// Already wrote the header; nothing useful to do but log.
		r.pdp.logger.Error("failed to encode JWKS", slog.Any("error", err))
	}
}

func (r *RAREndpoint) handleToken(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	if r.signer == nil {
		writeError(w, http.StatusServiceUnavailable, "server_error", "rar signer not configured")
		return
	}
	if err := req.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse form: "+err.Error())
		return
	}
	if got := req.PostForm.Get("grant_type"); got != grantTypeTokenExchange {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("expected %q, got %q", grantTypeTokenExchange, got))
		return
	}
	subjectToken := req.PostForm.Get("subject_token")
	if subjectToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}
	subjectTokenType := req.PostForm.Get("subject_token_type")
	switch subjectTokenType {
	case tokenTypeIDToken, tokenTypeAccessToken:
		// supported
	case "":
		writeError(w, http.StatusBadRequest, "invalid_request", "subject_token_type is required")
		return
	default:
		writeError(w, http.StatusBadRequest, "invalid_request",
			"unsupported subject_token_type "+subjectTokenType)
		return
	}
	requestedTokenType := req.PostForm.Get("requested_token_type")
	if requestedTokenType == "" {
		requestedTokenType = tokenTypeJWT
	}
	if requestedTokenType != tokenTypeJWT {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"only "+tokenTypeJWT+" is supported as requested_token_type")
		return
	}
	audience := req.PostForm.Get("audience")

	if r.verifier == nil {
		writeError(w, http.StatusServiceUnavailable, "server_error",
			"platform token verifier is not configured")
		return
	}
	verified, err := r.verifier.VerifyAccessToken(ctx, subjectToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token",
			"subject_token verification failed: "+err.Error())
		return
	}

	// Propagate the verified caller identity into the gRPC metadata the
	// downstream PDP reads via ctxAuth.GetClientIDFromContext. Without this,
	// GetDecisionMultiResource fails with "no metadata found within context".
	subject, _ := verified.Get("sub")
	subjectStr, _ := subject.(string)
	if subjectStr == "" {
		subjectStr = verified.Subject()
	}
	clientID := clientIDFromToken(verified)
	if clientID != "" {
		ctx = ctxAuth.EnrichIncomingContextMetadataWithAuthn(ctx, r.pdp.logger, clientID)
	}
	// The PDP emits audit events through audit.LogAuditEvent which expects an
	// auditTransaction in context. The normal HTTP/Connect interceptor chain
	// would set this up; the RAR endpoint installs its own transaction keyed
	// on the verified subject so that decisions are still audited.
	actorID := subjectStr
	if actorID == "" {
		actorID = clientID
	}
	ctx = audit.ContextWithActorID(ctx, actorID)

	requestedDetails, err := parseAuthorizationDetails(req.PostForm.Get("authorization_details"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_authorization_details", err.Error())
		return
	}
	if len(requestedDetails) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_authorization_details",
			"at least one authorization_details entry is required")
		return
	}
	for i, d := range requestedDetails {
		if err := validateDetail(d); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_authorization_details",
				fmt.Sprintf("entry %d: %s", i, err.Error()))
			return
		}
	}

	granted, err := r.evaluate(ctx, subjectToken, requestedDetails)
	if err != nil {
		r.pdp.logger.ErrorContext(ctx, "rar PDP evaluation failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "server_error",
			"policy evaluation failed")
		return
	}
	if len(granted) == 0 {
		// Nothing was permitted — RFC 9396 §6.1 mandates access_denied.
		writeError(w, http.StatusForbidden, "access_denied",
			"none of the requested authorization_details were granted")
		return
	}

	signed, exp, err := r.signer.Issue(subjectStr, audience, granted)
	if err != nil {
		r.pdp.logger.ErrorContext(ctx, "rar token sign failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not mint access token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(tokenExchangeResponse{
		AccessToken:          signed,
		IssuedTokenType:      tokenTypeJWT,
		TokenType:            "Bearer",
		ExpiresIn:            int64(time.Until(exp).Seconds()),
		AuthorizationDetails: granted,
	}); err != nil {
		r.pdp.logger.Error("failed to encode rar response", slog.Any("error", err))
	}
}

// evaluate fans the requested details out to the existing v2 PDP and returns
// only the (action, location) combinations that PERMIT.
func (r *RAREndpoint) evaluate(ctx context.Context, subjectToken string, requested []AuthorizationDetail) ([]AuthorizationDetail, error) {
	granted := make([]AuthorizationDetail, 0, len(requested))
	for _, detail := range requested {
		grantedActions := make([]string, 0, len(detail.Actions))
		grantedLocations := make(map[string]struct{})
		for _, actionName := range detail.Actions {
			permitted, err := r.decideAction(ctx, subjectToken, actionName, detail.Locations)
			if err != nil {
				return nil, fmt.Errorf("action %q: %w", actionName, err)
			}
			if len(permitted) == 0 {
				continue
			}
			grantedActions = append(grantedActions, actionName)
			for _, loc := range permitted {
				grantedLocations[loc] = struct{}{}
			}
		}
		if len(grantedActions) == 0 {
			continue
		}
		locations := make([]string, 0, len(grantedLocations))
		// Preserve request order — RFC 9396 is silent on ordering, but
		// stability makes the response predictable.
		for _, loc := range detail.Locations {
			if _, ok := grantedLocations[loc]; ok {
				locations = append(locations, loc)
			}
		}
		grantedDetail := detail
		grantedDetail.Actions = grantedActions
		grantedDetail.Locations = locations
		granted = append(granted, grantedDetail)
	}
	return granted, nil
}

func (r *RAREndpoint) decideAction(ctx context.Context, subjectToken, actionName string, locations []string) ([]string, error) {
	if len(locations) == 0 {
		return nil, nil
	}
	resources := make([]*authzV2.Resource, 0, len(locations))
	for i, loc := range locations {
		resources = append(resources, &authzV2.Resource{
			EphemeralId: fmt.Sprintf("loc-%d", i),
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{
					Fqns: []string{loc},
				},
			},
		})
	}
	req := connect.NewRequest(&authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{
				Token: &entity.Token{
					EphemeralId: "rar-subject",
					Jwt:         subjectToken,
				},
			},
		},
		Action:    &policy.Action{Name: actionName},
		Resources: resources,
	})
	resp, err := r.pdp.GetDecisionMultiResource(ctx, req)
	if err != nil {
		return nil, err
	}
	permitted := make([]string, 0, len(resources))
	for i, rd := range resp.Msg.GetResourceDecisions() {
		if rd.GetDecision() == authzV2.Decision_DECISION_PERMIT {
			permitted = append(permitted, locations[i])
		}
	}
	return permitted, nil
}

// parseAuthorizationDetails decodes the RFC 9396 array — accepted as either a
// JSON array literal or a JSON-encoded string (browsers tend to URL-encode it
// either way, but the body parser already URL-decoded).
func parseAuthorizationDetails(raw string) ([]AuthorizationDetail, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var details []AuthorizationDetail
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		// Try unwrapping one layer of JSON-string-ification (some clients
		// double-encode when stuffing into form bodies).
		var inner string
		if jerr := json.Unmarshal([]byte(raw), &inner); jerr == nil {
			if err2 := json.Unmarshal([]byte(inner), &details); err2 == nil {
				return details, nil
			}
		}
		return nil, fmt.Errorf("could not decode authorization_details: %w", err)
	}
	return details, nil
}

func validateDetail(d AuthorizationDetail) error {
	if d.Type == "" {
		return errors.New("type is required")
	}
	if d.Type != detailTypeOpenTDFAttribute {
		return fmt.Errorf("unsupported type %q (expected %q)", d.Type, detailTypeOpenTDFAttribute)
	}
	if len(d.Actions) == 0 {
		return errors.New("actions is required")
	}
	if len(d.Locations) == 0 {
		return errors.New("locations is required")
	}
	return nil
}

// clientIDFromToken pulls the OAuth client identifier from the verified
// subject token, falling back to the subject claim when client_id is absent
// (some IdPs only set "azp" or omit it for user-flow tokens).
func clientIDFromToken(verified jwtToken) string {
	for _, claim := range []string{"client_id", "azp"} {
		if v, ok := verified.Get(claim); ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return verified.Subject()
}

// jwtToken is the surface area of jwt.Token actually used here; declaring it
// locally lets the test substitute a lightweight stub without pulling jwx in.
type jwtToken interface {
	Get(string) (any, bool)
	Subject() string
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(rarErrorResponse{Error: code, ErrorDescription: description})
}
