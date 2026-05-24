// Package authorization adds an RFC 8693 token-exchange endpoint that issues
// access tokens carrying RFC 9396 authorization_details claims. The endpoint
// implements the Entitlement PDP described in the
// entitlement-vs-access-PDP taxonomy: it materializes a grant set for the
// subject and embeds it in a signed token. Resource servers run the local
// Access PDP (service/access/local) against the resulting token to render
// per-request boolean decisions.
//
// Two request modes are supported:
//
//   - Full materialization (no authorization_details supplied): the endpoint
//     calls GetEntitlements once, then GetDecisionMultiResource per action to
//     attach triggered obligations. Every (action × resource) combination the
//     subject is entitled to ends up in the token. This is the canonical
//     Entitlement PDP shape — the client doesn't pre-declare what it wants.
//
//   - Projection (authorization_details supplied): the endpoint narrows the
//     materialized set to the requested actions and locations. Useful for
//     audience-scoped or short-lived tokens that should carry only a subset
//     of the subject's full entitlements.
//
// This endpoint is NOT a full OAuth 2.0 Authorization Server — no /authorize,
// no PKCE, no refresh tokens, no client registration. It performs token
// decoration on a subject_token verified by the platform's existing
// AccessTokenVerifier. Signing keys are ephemeral; restart rotates them.
package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/access/local"
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

	rarTokenPath = "/v2/authorization/token"
	rarJWKSPath  = "/v2/authorization/jwks.json"
)

// authzDetailRequest is a parsed authorization_details entry from the inbound
// request. The wire shape matches RFC 9396; only the fields meaningful to
// projection are retained, the rest are dropped since the issuer owns the
// grant schema (clients don't get to inject arbitrary keys).
type authzDetailRequest struct {
	Type      string   `json:"type"`
	Actions   []string `json:"actions,omitempty"`
	Locations []string `json:"locations,omitempty"`
}

// tokenExchangeResponse follows RFC 8693 §2.2.
type tokenExchangeResponse struct {
	AccessToken          string        `json:"access_token"`
	IssuedTokenType      string        `json:"issued_token_type"`
	TokenType            string        `json:"token_type"`
	ExpiresIn            int64         `json:"expires_in"`
	AuthorizationDetails []local.Grant `json:"authorization_details,omitempty"`
}

// rarErrorResponse follows RFC 6749 §5.2.
type rarErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RAREndpoint owns the dependencies for the token issuance flow. The PDP
// dependency is the same Service that hosts GetEntitlements/GetDecision*, so
// policy reuse is implicit — no second copy of the entitlement store.
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

	subject, _ := verified.Get("sub")
	subjectStr, _ := subject.(string)
	if subjectStr == "" {
		subjectStr = verified.Subject()
	}
	clientID := clientIDFromToken(verified)
	if clientID != "" {
		ctx = ctxAuth.EnrichIncomingContextMetadataWithAuthn(ctx, r.pdp.logger, clientID)
	}
	actorID := subjectStr
	if actorID == "" {
		actorID = clientID
	}
	ctx = audit.ContextWithActorID(ctx, actorID)

	filter, err := parseAuthorizationDetails(req.PostForm.Get("authorization_details"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_authorization_details", err.Error())
		return
	}
	for i, d := range filter {
		if err := validateProjectionFilter(d); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_authorization_details",
				fmt.Sprintf("entry %d: %s", i, err.Error()))
			return
		}
	}

	grants, err := r.materialize(ctx, subjectToken, filter)
	if err != nil {
		r.pdp.logger.ErrorContext(ctx, "rar PDP evaluation failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "server_error",
			"policy evaluation failed")
		return
	}
	if len(grants) == 0 {
		// No materialized grants. RFC 9396 §6.1 mandates access_denied when
		// the request was a filtered projection; for unfiltered "give me
		// everything" calls a permissionless subject is also access_denied —
		// returning an empty allow-list would be just as denying without the
		// hint that the request was processed correctly.
		writeError(w, http.StatusForbidden, "access_denied",
			"subject has no entitlements that match the request")
		return
	}

	signed, exp, err := r.signer.Issue(subjectStr, audience, grants)
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
		AuthorizationDetails: grants,
	}); err != nil {
		r.pdp.logger.Error("failed to encode rar response", slog.Any("error", err))
	}
}

// materialize produces the materialized grant set. When filter is empty the
// full entitlement set is materialized; otherwise the set is projected to
// (actions × locations) intersection of the filter.
func (r *RAREndpoint) materialize(ctx context.Context, subjectToken string, filter []authzDetailRequest) ([]local.Grant, error) {
	entitled, err := r.entitlementsByAction(ctx, subjectToken)
	if err != nil {
		return nil, err
	}
	if len(filter) > 0 {
		entitled = applyProjectionFilter(entitled, filter)
	}
	return r.attachObligationsAndGroup(ctx, subjectToken, entitled)
}

// entitlementsByAction asks the existing Entitlement PDP for the subject's
// full grant set, then inverts the (fqn → actions) map into (action → fqns)
// — the orientation needed for the per-action GetDecisionMultiResource calls
// that follow.
func (r *RAREndpoint) entitlementsByAction(ctx context.Context, subjectToken string) (map[string][]string, error) {
	req := connect.NewRequest(&authzV2.GetEntitlementsRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{
				Token: &entity.Token{
					EphemeralId: "rar-subject",
					Jwt:         subjectToken,
				},
			},
		},
	})
	resp, err := r.pdp.GetEntitlements(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get entitlements: %w", err)
	}
	byAction := make(map[string]map[string]struct{})
	for _, ent := range resp.Msg.GetEntitlements() {
		for fqn, actions := range ent.GetActionsPerAttributeValueFqn() {
			for _, a := range actions.GetActions() {
				name := a.GetName()
				if name == "" {
					continue
				}
				if _, ok := byAction[name]; !ok {
					byAction[name] = map[string]struct{}{}
				}
				byAction[name][strings.ToLower(fqn)] = struct{}{}
			}
		}
	}
	out := make(map[string][]string, len(byAction))
	for action, set := range byAction {
		locations := make([]string, 0, len(set))
		for fqn := range set {
			locations = append(locations, fqn)
		}
		sort.Strings(locations)
		out[action] = locations
	}
	return out, nil
}

// applyProjectionFilter narrows the entitled set so only actions and
// locations referenced in the filter remain. Filter entries whose location
// the subject is not entitled to are silently dropped (denied — not an
// error), matching the per-resource semantics of GetDecisionMultiResource.
func applyProjectionFilter(entitled map[string][]string, filter []authzDetailRequest) map[string][]string {
	if len(filter) == 0 {
		return entitled
	}
	allowedActions := map[string]struct{}{}
	allowedLocations := map[string]struct{}{}
	for _, f := range filter {
		for _, a := range f.Actions {
			allowedActions[a] = struct{}{}
		}
		for _, l := range f.Locations {
			allowedLocations[strings.ToLower(l)] = struct{}{}
		}
	}
	out := make(map[string][]string)
	for action, locations := range entitled {
		if _, ok := allowedActions[action]; !ok {
			continue
		}
		kept := make([]string, 0, len(locations))
		for _, loc := range locations {
			if _, ok := allowedLocations[loc]; ok {
				kept = append(kept, loc)
			}
		}
		if len(kept) > 0 {
			out[action] = kept
		}
	}
	return out
}

// attachObligationsAndGroup calls GetDecisionMultiResource once per action to
// (a) confirm the Access PDP also permits each entitled (action, location) —
// it always should, but rules like attribute hierarchy may add constraints —
// and (b) pull the per-resource obligations the Obligation PDP wants the PEP
// to fulfill. Every known obligation value FQN is passed as "fulfillable" so
// the PDP treats unfulfilled obligations as informational rather than as a
// reason to deny: at materialization time we want the obligations recorded
// in the grant, not enforced. The downstream PEP enforces at access time
// using the local Access PDP.
//
// Results are grouped into local.Grant entries sharing the same
// (action, obligation-set) combination so the token stays compact.
func (r *RAREndpoint) attachObligationsAndGroup(ctx context.Context, subjectToken string, entitled map[string][]string) ([]local.Grant, error) {
	fulfillable, err := r.allObligationValueFQNs(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate obligations: %w", err)
	}
	// Stable iteration so the output ordering is deterministic — useful for
	// debugging, audit logs, and tests.
	actions := make([]string, 0, len(entitled))
	for a := range entitled {
		actions = append(actions, a)
	}
	sort.Strings(actions)

	type bucketKey struct {
		action      string
		obligations string
	}
	type bucket struct {
		action      string
		obligations []string
		locations   []string
	}
	buckets := make(map[bucketKey]*bucket)
	bucketOrder := make([]bucketKey, 0)

	for _, action := range actions {
		locations := entitled[action]
		if len(locations) == 0 {
			continue
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
		decisionReq := connect.NewRequest(&authzV2.GetDecisionMultiResourceRequest{
			EntityIdentifier: &authzV2.EntityIdentifier{
				Identifier: &authzV2.EntityIdentifier_Token{
					Token: &entity.Token{
						EphemeralId: "rar-subject",
						Jwt:         subjectToken,
					},
				},
			},
			Action:                    &policy.Action{Name: action},
			Resources:                 resources,
			FulfillableObligationFqns: fulfillable,
		})
		resp, err := r.pdp.GetDecisionMultiResource(ctx, decisionReq)
		if err != nil {
			return nil, fmt.Errorf("decide action %q: %w", action, err)
		}
		for i, rd := range resp.Msg.GetResourceDecisions() {
			if rd.GetDecision() != authzV2.Decision_DECISION_PERMIT {
				continue
			}
			obligations := append([]string(nil), rd.GetRequiredObligations()...)
			sort.Strings(obligations)
			key := bucketKey{action: action, obligations: strings.Join(obligations, "\x00")}
			b, ok := buckets[key]
			if !ok {
				b = &bucket{action: action, obligations: obligations}
				buckets[key] = b
				bucketOrder = append(bucketOrder, key)
			}
			b.locations = append(b.locations, locations[i])
		}
	}

	grants := make([]local.Grant, 0, len(buckets))
	for _, key := range bucketOrder {
		b := buckets[key]
		sort.Strings(b.locations)
		g := local.Grant{
			Type:      local.GrantTypeAttribute,
			Actions:   []string{b.action},
			Locations: b.locations,
		}
		if len(b.obligations) > 0 {
			g.Obligations = b.obligations
		}
		grants = append(grants, g)
	}
	return grants, nil
}

// parseAuthorizationDetails decodes the RFC 9396 array — accepted as either a
// JSON array literal or a JSON-encoded string (browsers tend to URL-encode it
// either way, but the body parser already URL-decoded). Returns nil when the
// caller omitted the parameter, signalling "materialize everything".
func parseAuthorizationDetails(raw string) ([]authzDetailRequest, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var details []authzDetailRequest
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

func validateProjectionFilter(d authzDetailRequest) error {
	if d.Type == "" {
		return errors.New("type is required")
	}
	if d.Type != local.GrantTypeAttribute {
		return fmt.Errorf("unsupported type %q (expected %q)", d.Type, local.GrantTypeAttribute)
	}
	if len(d.Actions) == 0 {
		return errors.New("actions is required")
	}
	if len(d.Locations) == 0 {
		return errors.New("locations is required")
	}
	return nil
}

// allObligationValueFQNs enumerates every obligation value FQN in the policy
// snapshot, used as the fulfillable set when running the Access PDP at
// materialization time so obligations are reported as required without
// causing a deny.
func (r *RAREndpoint) allObligationValueFQNs(ctx context.Context) ([]string, error) {
	store, ok := r.pdp.cache.(interface {
		ListAllObligations(ctx context.Context) ([]*policy.Obligation, error)
	})
	if !ok {
		return nil, nil
	}
	obls, err := store.ListAllObligations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0)
	for _, o := range obls {
		for _, v := range o.GetValues() {
			if fqn := v.GetFqn(); fqn != "" {
				out = append(out, fqn)
			}
		}
	}
	return out, nil
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
