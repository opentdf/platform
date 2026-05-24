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

	details := []AuthorizationDetail{
		{
			Type:      detailTypeOpenTDFAttribute,
			Actions:   []string{"read"},
			Locations: []string{"https://example.com/attr/classification/value/secret"},
		},
	}
	signed, exp, err := signer.Issue("user-1", "kas.example", details)
	require.NoError(t, err)
	assert.True(t, exp.After(time.Now()))

	// Resource server side: pull the public JWKS, parse the token against it.
	set := signer.JWKS()
	parsed, err := jwt.Parse(
		[]byte(signed),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer("https://opentdf.local"),
		jwt.WithAudience("kas.example"),
	)
	require.NoError(t, err)

	assert.Equal(t, "user-1", parsed.Subject())
	rawDetails, ok := parsed.Get("authorization_details")
	require.True(t, ok)
	rawJSON, err := json.Marshal(rawDetails)
	require.NoError(t, err)
	var roundTripped []AuthorizationDetail
	require.NoError(t, json.Unmarshal(rawJSON, &roundTripped))
	require.Len(t, roundTripped, 1)
	assert.Equal(t, details[0].Type, roundTripped[0].Type)
	assert.Equal(t, details[0].Actions, roundTripped[0].Actions)
	assert.Equal(t, details[0].Locations, roundTripped[0].Locations)
}

func TestRARSigner_JWKSContainsPublicKeyOnly(t *testing.T) {
	signer, err := NewEphemeralRARSigner("iss", time.Minute)
	require.NoError(t, err)

	set := signer.JWKS()
	require.Equal(t, 1, set.Len())
	pub, _ := set.Key(0)
	// Symbol() / KeyType for OKP is "OKP"; signing key would be private.
	assert.Equal(t, jwa.OKP, pub.KeyType())
	// A public Ed25519 key must NOT serialize a "d" (private scalar) parameter.
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
		raw, _ := json.Marshal(inner) // produces a JSON string literal
		got, err := parseAuthorizationDetails(string(raw))
		require.NoError(t, err)
		require.Len(t, got, 1)
	})
	t.Run("empty", func(t *testing.T) {
		got, err := parseAuthorizationDetails("")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("garbage", func(t *testing.T) {
		_, err := parseAuthorizationDetails("not json")
		require.Error(t, err)
	})
}

func TestValidateDetail(t *testing.T) {
	good := AuthorizationDetail{
		Type:      detailTypeOpenTDFAttribute,
		Actions:   []string{"read"},
		Locations: []string{"https://x"},
	}
	require.NoError(t, validateDetail(good))

	cases := map[string]AuthorizationDetail{
		"missing type":      {Actions: []string{"read"}, Locations: []string{"x"}},
		"wrong type":        {Type: "other", Actions: []string{"read"}, Locations: []string{"x"}},
		"missing actions":   {Type: detailTypeOpenTDFAttribute, Locations: []string{"x"}},
		"missing locations": {Type: detailTypeOpenTDFAttribute, Actions: []string{"read"}},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateDetail(d))
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
`

// stubVerifier accepts a fixed subject token and returns a synthetic jwt.Token.
// In production this would be the IdP-backed verifier from internal/auth.
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

// stubERS returns a fixed entity representation regardless of input — the test
// owns the policy file, so it owns what selectors need to match.
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

func TestRAREndpoint_GrantsPermittedDetails(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("audience", "kas.example")
	form.Set("authorization_details", `[
        {
            "type": "opentdf_attribute",
            "actions": ["read"],
            "locations": [
                "https://example.com/attr/classification/value/secret",
                "https://example.com/attr/classification/value/public"
            ]
        }
    ]`)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body tokenExchangeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "Bearer", body.TokenType)
	assert.Equal(t, tokenTypeJWT, body.IssuedTokenType)
	assert.Greater(t, body.ExpiresIn, int64(0))
	require.Len(t, body.AuthorizationDetails, 1)
	got := body.AuthorizationDetails[0]
	assert.Equal(t, []string{"read"}, got.Actions)
	assert.ElementsMatch(t,
		[]string{
			"https://example.com/attr/classification/value/secret",
			"https://example.com/attr/classification/value/public",
		}, got.Locations)

	// Verify the issued JWT is valid under the published JWKS.
	parsed, err := jwt.Parse(
		[]byte(body.AccessToken),
		jwt.WithKeySet(endpoint.signer.JWKS()),
		jwt.WithValidate(true),
		jwt.WithIssuer("https://opentdf.local"),
		jwt.WithAudience("kas.example"),
	)
	require.NoError(t, err)
	assert.Equal(t, "user-1", parsed.Subject())
}

func TestRAREndpoint_FiltersOutDeniedLocations(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "none")
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("authorization_details", `[
        {
            "type": "opentdf_attribute",
            "actions": ["read"],
            "locations": [
                "https://example.com/attr/classification/value/secret",
                "https://example.com/attr/classification/value/public"
            ]
        }
    ]`)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body tokenExchangeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.AuthorizationDetails, 1)
	got := body.AuthorizationDetails[0]
	// "none" clearance: only the /public mapping matches.
	assert.Equal(t, []string{"https://example.com/attr/classification/value/public"}, got.Locations)
}

func TestRAREndpoint_DeniesWhenNothingPermitted(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "")
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("authorization_details", `[
        {
            "type": "opentdf_attribute",
            "actions": ["read"],
            "locations": ["https://example.com/attr/classification/value/secret"]
        }
    ]`)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body rarErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "access_denied", body.Error)
}

func TestRAREndpoint_RejectsBadSubjectToken(t *testing.T) {
	endpoint, _ := newTestEndpoint(t, "topsecret")
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "wrong-token")
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("authorization_details", `[{"type":"opentdf_attribute","actions":["read"],"locations":["x"]}]`)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRAREndpoint_RejectsWrongGrantType(t *testing.T) {
	endpoint, _ := newTestEndpoint(t, "topsecret")
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
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
	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + rarJWKSPath)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	set, err := jwk.ParseReader(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 1, set.Len())
}
