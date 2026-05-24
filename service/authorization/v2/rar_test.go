package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/access/local"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/filestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/structpb"
)

// --- Signer ------------------------------------------------------------------

func TestRARSigner_RoundTripSignAndVerify(t *testing.T) {
	signer, err := NewEphemeralRARSigner("https://opentdf.local", time.Hour)
	require.NoError(t, err)

	grants := []local.Grant{
		{
			Type:      local.GrantTypeAttribute,
			Actions:   []string{"read"},
			Locations: []string{"https://example.com/attr/classification/value/secret"},
		},
	}
	signed, exp, err := signer.Issue("user-1", "kas.example", grants)
	require.NoError(t, err)
	assert.True(t, exp.After(time.Now()))

	// Resource server side: pull the public JWKS, parse the token against it,
	// hand the parsed token to the local Access PDP.
	parsed, err := jwt.Parse([]byte(signed),
		jwt.WithKeySet(signer.JWKS()),
		jwt.WithValidate(true),
		jwt.WithIssuer("https://opentdf.local"),
		jwt.WithAudience("kas.example"),
	)
	require.NoError(t, err)
	got, err := local.GrantsFromToken(parsed)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, grants[0].Actions, got[0].Actions)
	assert.Equal(t, grants[0].Locations, got[0].Locations)

	// And the local Access PDP renders the expected boolean.
	d := local.Decide(got, "read", "https://example.com/attr/classification/value/secret")
	assert.True(t, d.Allow)
}

func TestRARSigner_JWKSContainsPublicKeyOnly(t *testing.T) {
	signer, err := NewEphemeralRARSigner("iss", time.Minute)
	require.NoError(t, err)
	set := signer.JWKS()
	require.Equal(t, 1, set.Len())
	pub, _ := set.Key(0)
	assert.Equal(t, jwa.OKP, pub.KeyType())
	buf, err := json.Marshal(pub)
	require.NoError(t, err)
	assert.NotContains(t, string(buf), `"d":`, "public JWK leaked private scalar")
}

// --- Parsing & validation ----------------------------------------------------

func TestParseAuthorizationDetails(t *testing.T) {
	t.Run("array", func(t *testing.T) {
		raw := `[{"type":"opentdf_attribute","actions":["read"],"locations":["https://x/y/value/z"]}]`
		got, err := parseAuthorizationDetails(raw)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "opentdf_attribute", got[0].Type)
	})
	t.Run("double-encoded", func(t *testing.T) {
		inner := `[{"type":"opentdf_attribute","actions":["read"],"locations":["https://x/y/value/z"]}]`
		raw, _ := json.Marshal(inner)
		got, err := parseAuthorizationDetails(string(raw))
		require.NoError(t, err)
		require.Len(t, got, 1)
	})
	t.Run("empty signals full materialization", func(t *testing.T) {
		got, err := parseAuthorizationDetails("")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("garbage", func(t *testing.T) {
		_, err := parseAuthorizationDetails("not json")
		require.Error(t, err)
	})
}

func TestValidateProjectionFilter(t *testing.T) {
	good := authzDetailRequest{Type: local.GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{"https://x"}}
	require.NoError(t, validateProjectionFilter(good))

	cases := map[string]authzDetailRequest{
		"missing type":      {Actions: []string{"read"}, Locations: []string{"x"}},
		"wrong type":        {Type: "other", Actions: []string{"read"}, Locations: []string{"x"}},
		"missing actions":   {Type: local.GrantTypeAttribute, Locations: []string{"x"}},
		"missing locations": {Type: local.GrantTypeAttribute, Actions: []string{"read"}},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateProjectionFilter(d))
		})
	}
}

// --- End-to-end via httptest -------------------------------------------------

const integrationPolicy = `
namespaces:
  - name: example.com
attributes:
  - namespace: example.com
    name: classification
    rule: anyOf
    values:
      - value: secret
      - value: public
subject_mappings:
  - attribute_value_fqn: https://example.com/attr/classification/value/secret
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .clearance
                  operator: IN
                  subject_external_values: [topsecret]
    actions:
      - name: read
  - attribute_value_fqn: https://example.com/attr/classification/value/public
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .clearance
                  operator: IN
                  subject_external_values: [topsecret, none]
    actions:
      - name: read
obligations:
  - namespace: example.com
    name: watermark
    values:
      - value: required
        triggers:
          - attribute_value_fqn: https://example.com/attr/classification/value/secret
            action: read
`

type stubVerifier struct {
	expectedToken string
	subject       string
}

func (s *stubVerifier) VerifyAccessToken(_ context.Context, tokenRaw string) (jwt.Token, error) {
	if tokenRaw != s.expectedToken {
		return nil, assertError("unexpected subject token")
	}
	t := jwt.New()
	_ = t.Set(jwt.SubjectKey, s.subject)
	_ = t.Set(jwt.IssuerKey, "https://idp.example")
	return t, nil
}

type assertError string

func (a assertError) Error() string { return string(a) }

type stubERS struct {
	props map[string]interface{}
}

func (s *stubERS) ResolveEntities(_ context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	st, err := structpb.NewStruct(s.props)
	if err != nil {
		return nil, err
	}
	reps := make([]*entityresolutionV2.EntityRepresentation, len(req.GetEntities()))
	for i, e := range req.GetEntities() {
		reps[i] = &entityresolutionV2.EntityRepresentation{
			OriginalId:      e.GetEphemeralId(),
			AdditionalProps: []*structpb.Struct{st},
		}
	}
	return &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: reps}, nil
}

func (s *stubERS) CreateEntityChainsFromTokens(_ context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	chains := make([]*entity.EntityChain, 0, len(req.GetTokens()))
	for _, tok := range req.GetTokens() {
		chains = append(chains, &entity.EntityChain{
			EphemeralId: tok.GetEphemeralId(),
			Entities: []*entity.Entity{
				{
					EphemeralId: "subject",
					Category:    entity.Entity_CATEGORY_SUBJECT,
					EntityType:  &entity.Entity_ClientId{ClientId: "rar-test-client"},
				},
			},
		})
	}
	return &entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: chains}, nil
}

var _ sdkconnect.EntityResolutionServiceClientV2 = (*stubERS)(nil)

func newTestEndpoint(t *testing.T, clearance string) (*RAREndpoint, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(integrationPolicy), 0o600))
	store, err := filestore.NewStoreFromFile(path)
	require.NoError(t, err)

	svc := &Service{
		sdk: &otdf.SDK{
			EntityResolutionV2: &stubERS{props: map[string]interface{}{"clearance": clearance}},
		},
		logger: logger.CreateTestLogger(),
		config: &Config{},
		Tracer: noop.NewTracerProvider().Tracer(""),
		cache:  store,
	}
	signer, err := NewEphemeralRARSigner("https://opentdf.local", time.Hour)
	require.NoError(t, err)

	endpoint := &RAREndpoint{
		pdp:      svc,
		signer:   signer,
		verifier: &stubVerifier{expectedToken: "subject-token", subject: "user-1"},
	}
	return endpoint, "subject-token"
}

// Full materialization: no authorization_details supplied. Endpoint should
// return the subject's complete entitlement set as a signed grant claim.
func TestRAREndpoint_MaterializesFullEntitlementsByDefault(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("audience", "kas.example")
	// Note: no authorization_details — we expect EVERYTHING.

	body := doTokenRequest(t, srv.URL, form)
	require.Equal(t, "Bearer", body.TokenType)
	require.NotEmpty(t, body.AccessToken)

	// Both locations the subject is entitled to should be present.
	allLocations := []string{}
	for _, g := range body.AuthorizationDetails {
		allLocations = append(allLocations, g.Locations...)
	}
	assert.ElementsMatch(t,
		[]string{
			"https://example.com/attr/classification/value/secret",
			"https://example.com/attr/classification/value/public",
		}, allLocations)

	// Drive the local Access PDP against the issued token end-to-end.
	parsed, err := jwt.Parse([]byte(body.AccessToken),
		jwt.WithKeySet(endpoint.signer.JWKS()),
		jwt.WithValidate(true),
		jwt.WithIssuer("https://opentdf.local"),
		jwt.WithAudience("kas.example"),
	)
	require.NoError(t, err)
	grants, err := local.GrantsFromToken(parsed)
	require.NoError(t, err)

	// /secret: permitted AND carries the watermark obligation.
	dSecret := local.Decide(grants, "read", "https://example.com/attr/classification/value/secret")
	assert.True(t, dSecret.Allow)
	assert.Equal(t, []string{"https://example.com/obl/watermark/value/required"}, dSecret.RequiredObligations)

	// /public: permitted, no obligation.
	dPublic := local.Decide(grants, "read", "https://example.com/attr/classification/value/public")
	assert.True(t, dPublic.Allow)
	assert.Empty(t, dPublic.RequiredObligations)

	// An unrelated location is denied.
	dDeny := local.Decide(grants, "read", "https://example.com/attr/classification/value/topsecret")
	assert.False(t, dDeny.Allow)
}

// Grants with different obligation sets must end up in separate detail
// entries — otherwise the local PDP would over-attach obligations.
func TestRAREndpoint_GroupsByObligationSet(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	body := doTokenRequest(t, srv.URL, baseForm(subjectToken))
	// At least one grant should carry the obligation, at least one should not.
	var withOb, withoutOb int
	for _, g := range body.AuthorizationDetails {
		if len(g.Obligations) > 0 {
			withOb++
		} else {
			withoutOb++
		}
	}
	assert.GreaterOrEqual(t, withOb, 1, "expected an obligation-bearing grant")
	assert.GreaterOrEqual(t, withoutOb, 1, "expected an obligation-free grant")
}

// Projection: client supplies authorization_details to narrow the issued
// token to a subset of the subject's entitlements.
func TestRAREndpoint_ProjectionNarrowsToFilter(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := baseForm(subjectToken)
	form.Set("authorization_details", `[
        {"type":"opentdf_attribute",
         "actions":["read"],
         "locations":["https://example.com/attr/classification/value/public"]}
    ]`)
	body := doTokenRequest(t, srv.URL, form)

	require.Len(t, body.AuthorizationDetails, 1)
	got := body.AuthorizationDetails[0]
	assert.Equal(t, []string{"https://example.com/attr/classification/value/public"}, got.Locations)
	// The secret entitlement is filtered out by the projection even though
	// the subject is entitled to it.
	parsed, err := jwt.Parse([]byte(body.AccessToken),
		jwt.WithKeySet(endpoint.signer.JWKS()),
		jwt.WithValidate(true),
		jwt.WithIssuer("https://opentdf.local"),
	)
	require.NoError(t, err)
	grants, err := local.GrantsFromToken(parsed)
	require.NoError(t, err)
	assert.False(t, local.Decide(grants, "read", "https://example.com/attr/classification/value/secret").Allow)
}

// "none" clearance: subject is only entitled to /public via the second
// subject mapping. /secret is filtered by the Entitlement PDP itself.
func TestRAREndpoint_LowerClearanceMaterializesNarrowerSet(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "none")
	srv := newServer(endpoint)
	defer srv.Close()

	body := doTokenRequest(t, srv.URL, baseForm(subjectToken))
	all := []string{}
	for _, g := range body.AuthorizationDetails {
		all = append(all, g.Locations...)
	}
	assert.Equal(t, []string{"https://example.com/attr/classification/value/public"}, all)
}

// Subject with zero entitlements gets access_denied per RFC 9396 §6.1.
func TestRAREndpoint_DeniesWhenSubjectHasNoEntitlements(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "")
	srv := newServer(endpoint)
	defer srv.Close()

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(baseForm(subjectToken).Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body rarErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "access_denied", body.Error)
}

func TestRAREndpoint_RejectsBadSubjectToken(t *testing.T) {
	endpoint, _ := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "wrong-token")
	form.Set("subject_token_type", tokenTypeIDToken)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRAREndpoint_RejectsWrongGrantType(t *testing.T) {
	endpoint, _ := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRAREndpoint_JWKSEndpoint(t *testing.T) {
	endpoint, _ := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	resp, err := http.Get(srv.URL + rarJWKSPath)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	set, err := jwk.ParseReader(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 1, set.Len())
}

// --- helpers -----------------------------------------------------------------

func newServer(endpoint *RAREndpoint) *httptest.Server {
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	return httptest.NewServer(mux)
}

func baseForm(subjectToken string) url.Values {
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	return form
}

func doTokenRequest(t *testing.T, baseURL string, form url.Values) tokenExchangeResponse {
	t.Helper()
	resp, err := http.Post(baseURL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200; got %d", resp.StatusCode)
	var body tokenExchangeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}
