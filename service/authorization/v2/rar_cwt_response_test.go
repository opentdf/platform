package authorization

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/opentdf/platform/service/access/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// --- helpers ----------------------------------------------------------------

// stripCWTTag drops the optional RFC 8392 §6 CWT tag prefix (0xd8, 0x3d)
// so go-cose can parse the bare COSE_Sign1.
func stripCWTTag(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xd8 && b[1] == 0x3d {
		return b[2:]
	}
	return b
}

// fetchCOSEKeySet pulls and parses the platform's published COSE Key Set
// the same way an external PEP would.
func fetchCOSEKeySet(t *testing.T, baseURL string) []*ecdsa.PublicKey {
	t.Helper()
	resp, err := http.Get(baseURL + rarCOSEKeysPath)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, contentTypeCOSEK, resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var keys []map[int64]any
	require.NoError(t, cbor.Unmarshal(body, &keys))
	require.NotEmpty(t, keys)

	out := make([]*ecdsa.PublicKey, 0, len(keys))
	for _, k := range keys {
		x, _ := k[coseXLabel].([]byte)
		y, _ := k[coseYLabel].([]byte)
		require.NotEmpty(t, x)
		require.NotEmpty(t, y)
		out = append(out, ecKeyFromXY(x, y))
	}
	return out
}

func ecKeyFromXY(x, y []byte) *ecdsa.PublicKey {
	key := &ecdsa.PublicKey{Curve: elliptic.P256()}
	key.X = new(big.Int).SetBytes(x)
	key.Y = new(big.Int).SetBytes(y)
	return key
}

// --- tests ------------------------------------------------------------------

func TestRAREndpoint_CWTResponse_IsDefault(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	// Build a form with NO requested_token_type — the new default is CWT.
	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("audience", "kas.example")

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, contentTypeCWT, resp.Header.Get("Content-Type"))

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	// Verify the response is a real, signed COSE_Sign1 we can decode.
	cose1 := stripCWTTag(raw)
	var msg cose.Sign1Message
	require.NoError(t, msg.UnmarshalCBOR(cose1))

	// Decode the payload as a CBOR map and assert the standard claims plus
	// authorization_details are present.
	var claims map[any]any
	require.NoError(t, cbor.Unmarshal(msg.Payload, &claims))
	assert.Equal(t, "https://opentdf.local", claims[uint64(cwtClaimIss)])
	assert.Equal(t, "user-1", claims[uint64(cwtClaimSub)])
	assert.Equal(t, "kas.example", claims[uint64(cwtClaimAud)])
	details, ok := claims[local.AuthorizationDetailsClaim].([]any)
	require.True(t, ok, "expected authorization_details array, got %T", claims[local.AuthorizationDetailsClaim])
	require.NotEmpty(t, details)
}

func TestRAREndpoint_CWTResponse_VerifiesAgainstPublishedCOSEKeySet(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("requested_token_type", tokenTypeCWT)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)

	var msg cose.Sign1Message
	require.NoError(t, msg.UnmarshalCBOR(stripCWTTag(body)))

	// Pull keys from the platform's published COSE Key Set and verify the
	// response signature with one of them — proves the same key pair signs
	// the token and answers the COSE key endpoint.
	pubKeys := fetchCOSEKeySet(t, srv.URL)
	require.NotEmpty(t, pubKeys)

	verified := false
	for _, k := range pubKeys {
		v, err := cose.NewVerifier(cose.AlgorithmES256, k)
		require.NoError(t, err)
		if err := msg.Verify(nil, v); err == nil {
			verified = true
			break
		}
	}
	assert.True(t, verified, "no published COSE key verified the response signature")
}

func TestRAREndpoint_CWTResponse_DisabledWhenSignerMissing(t *testing.T) {
	// Build an endpoint with a JWT signer but no CWT signer — CWT response
	// must fall through to 400.
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()
	endpoint.cwtSigner = nil // simulate "CWT signer failed at startup"

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("requested_token_type", tokenTypeCWT)

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRAREndpoint_COSEKeysEndpoint(t *testing.T) {
	endpoint, _ := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	resp, err := http.Get(srv.URL + rarCOSEKeysPath)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, contentTypeCOSEK, resp.Header.Get("Content-Type"))
}

func TestRAREndpoint_JWTResponse_OptIn(t *testing.T) {
	// Clients explicitly asking for JWT keep getting the JSON envelope.
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("requested_token_type", tokenTypeJWT)

	body := doTokenRequest(t, srv.URL, form)
	require.NotEmpty(t, body.AccessToken)
	require.Equal(t, "Bearer", body.TokenType)
	require.Equal(t, tokenTypeJWT, body.IssuedTokenType)
}

func TestRAREndpoint_UnknownRequestedTokenTypeRejected(t *testing.T) {
	endpoint, subjectToken := newTestEndpoint(t, "topsecret")
	srv := newServer(endpoint)
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", tokenTypeIDToken)
	form.Set("requested_token_type", "urn:bogus:token-type")

	resp, err := http.Post(srv.URL+rarTokenPath, "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
