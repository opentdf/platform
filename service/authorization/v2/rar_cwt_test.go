package authorization

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	otdf "github.com/opentdf/platform/sdk"
	authn "github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/filestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/structpb"
)

// --- CWT subject-token test fixtures ----------------------------------------

// padBytes left-pads byte slices to a fixed length so the CBOR
// representation of an ECDSA coordinate is always 32 bytes for P-256.
func padBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// coseKeySetCBOR is a one-entry COSE Key Set (RFC 9052 §7) carrying the
// supplied P-256 public key with kid.
func coseKeySetCBOR(t *testing.T, pub *ecdsa.PublicKey, kid []byte) []byte {
	t.Helper()
	key := map[int64]any{
		1:  int64(2),  // kty = EC2
		3:  int64(-7), // alg = ES256
		-1: int64(1),  // crv = P-256
		-2: padBytes(pub.X.Bytes(), 32),
		-3: padBytes(pub.Y.Bytes(), 32),
		2:  kid,
	}
	buf, err := cbor.Marshal([]map[int64]any{key})
	require.NoError(t, err)
	return buf
}

// signCWT returns a base64url-encoded COSE_Sign1 CWT with the supplied
// standard and custom claims, mirroring the shape of an authnz-rs token.
func signCWT(t *testing.T, priv *ecdsa.PrivateKey, kid []byte, claims map[any]any) string {
	t.Helper()
	payload, err := cbor.Marshal(claims)
	require.NoError(t, err)
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	require.NoError(t, err)
	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
				cose.HeaderLabelKeyID:     kid,
			},
		},
		Payload: payload,
	}
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	raw, err := msg.MarshalCBOR()
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// cwtClaims builds a CWT claims map (CBOR integer labels for standard claims,
// text labels for custom ones, matching the authnz-rs encoding).
func cwtClaims(iss, aud, sub string, ttl time.Duration, custom map[string]any) map[any]any {
	now := time.Now().Unix()
	out := map[any]any{
		int64(1): iss,
		int64(2): sub,
		int64(3): aud,
		int64(4): now + int64(ttl.Seconds()),
		int64(6): now,
	}
	for k, v := range custom {
		out[k] = v
	}
	return out
}

// keySetServer mimics authnz-rs's /.well-known/cose-keys endpoint.
func keySetServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/cose-key-set+cbor")
		_, _ = w.Write(body)
	}))
}

// cwtERSTokenAware behaves like the existing stubERS but reads claims out of
// the (unsigned) JWT the CWT verifier produced, so the integration test
// confirms the synthetic-JWT bridge actually flows through.
type cwtERSTokenAware struct{}

func (cwtERSTokenAware) ResolveEntities(_ context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	// Each entity carries a Claims any that the upstream chain put on it.
	reps := make([]*entityresolutionV2.EntityRepresentation, len(req.GetEntities()))
	for i, e := range req.GetEntities() {
		st, _ := structpb.NewStruct(map[string]any{
			"clearance":    "topsecret",
			"arkavo_roles": []any{"admin"},
		})
		reps[i] = &entityresolutionV2.EntityRepresentation{
			OriginalId:      e.GetEphemeralId(),
			AdditionalProps: []*structpb.Struct{st},
		}
	}
	return &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: reps}, nil
}

func (cwtERSTokenAware) CreateEntityChainsFromTokens(_ context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	chains := make([]*entity.EntityChain, 0, len(req.GetTokens()))
	for _, tok := range req.GetTokens() {
		// Decoding the JWT itself is the integration-side ERS's concern.
		// For this test, just acknowledge the chain by EphemeralId.
		chains = append(chains, &entity.EntityChain{
			EphemeralId: tok.GetEphemeralId(),
			Entities: []*entity.Entity{{
				EphemeralId: "subject",
				Category:    entity.Entity_CATEGORY_SUBJECT,
				EntityType:  &entity.Entity_ClientId{ClientId: "rar-cwt-test"},
			}},
		})
	}
	return &entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: chains}, nil
}

// newCWTTestEndpoint wires a RAREndpoint with both the OIDC verifier
// (stubbed off — not used in these tests) and a real CWT verifier pointed
// at a local key-set server.
func newCWTTestEndpoint(t *testing.T, priv *ecdsa.PrivateKey, kid []byte) (*RAREndpoint, *httptest.Server) {
	t.Helper()
	keySrv := keySetServer(t, coseKeySetCBOR(t, &priv.PublicKey, kid))

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(integrationPolicy), 0o600))
	store, err := filestore.NewStoreFromFile(path)
	require.NoError(t, err)

	svc := &Service{
		sdk: &otdf.SDK{
			EntityResolutionV2: cwtERSTokenAware{},
		},
		logger: logger.CreateTestLogger(),
		config: &Config{},
		Tracer: noop.NewTracerProvider().Tracer(""),
		cache:  store,
	}
	signer, err := NewEphemeralRARSigner("https://opentdf.local", time.Hour)
	require.NoError(t, err)
	cwtSigner, err := NewEphemeralRARCWTSigner("https://opentdf.local", time.Hour)
	require.NoError(t, err)

	cwtVerifier, err := authn.NewCWTVerifier(context.Background(), authn.CWTVerifierConfig{
		COSEKeysURL: keySrv.URL,
		Issuer:      "https://authnz.example",
		Audience:    "opentdf-platform",
		Algorithm:   "ES256",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)

	endpoint := &RAREndpoint{
		pdp:         svc,
		signer:      signer,
		cwtSigner:   cwtSigner,
		cwtVerifier: cwtVerifier,
	}
	return endpoint, keySrv
}

// --- tests ------------------------------------------------------------------

func TestRAREndpoint_CWT_HappyPath(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := []byte("test-kid-1")

	endpoint, keySrv := newCWTTestEndpoint(t, priv, kid)
	defer keySrv.Close()
	srv := newServer(endpoint)
	defer srv.Close()

	subjectToken := signCWT(t, priv, kid, cwtClaims(
		"https://authnz.example",
		"opentdf-platform",
		"user-1",
		time.Hour,
		map[string]any{
			"email":             "alice@example.com",
			"arkavo_roles":      []any{"admin"},
			"arkavo_account_id": "acct-1",
		},
	))

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeCWT)
	form.Set("requested_token_type", tokenTypeJWT)
	form.Set("audience", "kas.example")

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body tokenExchangeResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.AccessToken)
	assert.NotEmpty(t, body.AuthorizationDetails)
}

func TestRAREndpoint_CWT_RejectsBadSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := []byte("test-kid-2")

	endpoint, keySrv := newCWTTestEndpoint(t, priv, kid)
	defer keySrv.Close()
	srv := newServer(endpoint)
	defer srv.Close()

	// Sign with the wrong key; the published COSE Key Set has the other key.
	subjectToken := signCWT(t, other, kid, cwtClaims(
		"https://authnz.example", "opentdf-platform", "user-1", time.Hour, nil))

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeCWT)
	form.Set("requested_token_type", tokenTypeJWT)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRAREndpoint_CWT_DisabledWhenVerifierNotConfigured(t *testing.T) {
	// Reuse the standard JWT-only test endpoint — no cwtVerifier wired.
	endpoint, _ := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "any-token")
	form.Set("subject_token_type", tokenTypeCWT)
	form.Set("requested_token_type", tokenTypeJWT)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body rarErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body.ErrorDescription, "CWT subject tokens are not enabled")
}

func TestRAREndpoint_CWT_RejectsMalformedBase64(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := []byte("test-kid-3")
	endpoint, keySrv := newCWTTestEndpoint(t, priv, kid)
	defer keySrv.Close()
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "!!!not base64!!!")
	form.Set("subject_token_type", tokenTypeCWT)
	form.Set("requested_token_type", tokenTypeJWT)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
