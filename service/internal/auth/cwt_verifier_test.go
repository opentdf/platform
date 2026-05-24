package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// --- helpers ----------------------------------------------------------------

// newP256 returns a fresh ECDSA P-256 keypair plus the RFC 7638-style
// thumbprint we use as a kid throughout the tests.
func newP256(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := append([]byte("kid-"), byteSlicePad(priv.X.Bytes(), 4)...)
	return priv, kid
}

func byteSlicePad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// coseKeySetFromPub serializes a P-256 public key as a one-entry COSE Key
// Set CBOR (matching what authnz-rs publishes at /.well-known/cose-keys).
func coseKeySetFromPub(t *testing.T, pub *ecdsa.PublicKey, kid []byte) []byte {
	t.Helper()
	x := byteSlicePad(pub.X.Bytes(), 32)
	y := byteSlicePad(pub.Y.Bytes(), 32)
	key := map[int64]any{
		1:  int64(2),  // kty = EC2
		3:  int64(-7), // alg = ES256
		-1: int64(1),  // crv = P-256
		-2: x,
		-3: y,
		2:  kid, // kid
	}
	buf, err := cbor.Marshal([]map[int64]any{key})
	require.NoError(t, err)
	return buf
}

// signCWT signs a CWT with claims and returns base64url(COSE_Sign1) — the
// same wire format the RAR endpoint will accept as a subject_token.
func signCWT(t *testing.T, priv *ecdsa.PrivateKey, kid []byte, claims map[int64]any, custom map[string]any) string {
	t.Helper()
	// Encode claims as CBOR.
	payload := map[any]any{}
	for k, v := range claims {
		payload[k] = v
	}
	for k, v := range custom {
		payload[k] = v
	}
	payloadCBOR, err := cbor.Marshal(payload)
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
		Payload: payloadCBOR,
	}
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	raw, err := msg.MarshalCBOR()
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// keySetServer wraps a tiny httptest.Server that serves a COSE Key Set,
// mimicking authnz-rs's /.well-known/cose-keys.
func keySetServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/cose-key-set+cbor")
		_, _ = w.Write(body)
	}))
}

// standardClaims builds a CWT claims map with CBOR integer labels
// (RFC 8392 §4) for the standard registered claims used in tests.
// `sub` is parameterized for future tests even though every existing test
// uses "user-1".
//
//nolint:unparam // sub is intentionally parameterizable
func standardClaims(iss, aud, sub string, ttl time.Duration) map[int64]any {
	now := time.Now().Unix()
	return map[int64]any{
		1: iss,                        // iss
		2: sub,                        // sub
		3: aud,                        // aud
		4: now + int64(ttl.Seconds()), // exp
		6: now,                        // iat
	}
}

// --- tests ------------------------------------------------------------------

func TestCWTVerifier_HappyPath(t *testing.T) {
	priv, kid := newP256(t)
	keySet := coseKeySetFromPub(t, &priv.PublicKey, kid)
	srv := keySetServer(t, keySet)
	defer srv.Close()

	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		Algorithm:   "ES256",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)

	subjectToken := signCWT(t, priv, kid,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", time.Hour),
		map[string]any{
			"email":             "alice@example.com",
			"arkavo_roles":      []any{"user", "reader"},
			"arkavo_account_id": "acct-1234",
		},
	)
	tok, jwtStr, err := v.VerifyCWTSubjectToken(context.Background(), subjectToken)
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, "user-1", tok.Subject())
	require.NotEmpty(t, jwtStr)
	// Synthetic JWT is alg=none → ends with the trailing dot.
	require.Equal(t, byte('.'), jwtStr[len(jwtStr)-1])
}

func TestCWTVerifier_RejectsWrongIssuer(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	tok := signCWT(t, priv, kid,
		standardClaims("https://imposter.example", "opentdf-platform", "user-1", time.Hour),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iss mismatch")
}

func TestCWTVerifier_RejectsWrongAudience(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	tok := signCWT(t, priv, kid,
		standardClaims("https://idp.example", "some-other-rs", "user-1", time.Hour),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestCWTVerifier_RejectsExpired(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	tok := signCWT(t, priv, kid,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", -time.Minute),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestCWTVerifier_RejectsUnknownKid(t *testing.T) {
	priv1, kid1 := newP256(t)
	priv2, kid2 := newP256(t)
	// Server publishes priv1's public key.
	srv := keySetServer(t, coseKeySetFromPub(t, &priv1.PublicKey, kid1))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	// Sign with priv2 and kid2 — server doesn't know it.
	tok := signCWT(t, priv2, kid2,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", time.Hour),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify")
}

func TestCWTVerifier_RejectsMalformedBase64(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), "!!!not base64!!!")
	require.Error(t, err)
}

func TestCWTVerifier_RejectsMalformedCBOR(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	// Valid base64, decodes to non-COSE bytes.
	garbage := base64.RawURLEncoding.EncodeToString([]byte("not a cose_sign1"))
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), garbage)
	require.Error(t, err)
}

func TestCWTVerifier_CustomClaimsRoundTrip(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	subjectToken := signCWT(t, priv, kid,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", time.Hour),
		map[string]any{
			"arkavo_roles":        []any{"admin", "reader"},
			"arkavo_entitlements": []any{"tdf:create", "tdf:decrypt"},
			"arkavo_account_id":   "acct-9999",
			"idp":                 "webauthn",
			"email":               "bob@example.com",
		},
	)
	tok, _, err := v.VerifyCWTSubjectToken(context.Background(), subjectToken)
	require.NoError(t, err)

	roles, ok := tok.Get("arkavo_roles")
	require.True(t, ok)
	rolesSlice, ok := roles.([]any)
	require.True(t, ok)
	require.Len(t, rolesSlice, 2)
	assert.Equal(t, "admin", rolesSlice[0])

	idp, ok := tok.Get("idp")
	require.True(t, ok)
	assert.Equal(t, "webauthn", idp)
}

func TestCWTVerifier_AudienceArrayMatches(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	claims := standardClaims("https://idp.example", "", "user-1", time.Hour)
	claims[3] = []any{"some-other-rs", "opentdf-platform"} // aud as array
	tok := signCWT(t, priv, kid, claims, nil)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.NoError(t, err)
}

func TestNewCWTVerifier_RejectsBadConfig(t *testing.T) {
	cases := map[string]CWTVerifierConfig{
		"missing url":   {Issuer: "i", Audience: "a"},
		"missing iss":   {COSEKeysURL: "https://x", Audience: "a"},
		"missing aud":   {COSEKeysURL: "https://x", Issuer: "i"},
		"bad algorithm": {COSEKeysURL: "https://x", Issuer: "i", Audience: "a", Algorithm: "RS256"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewCWTVerifier(context.Background(), c, nil)
			require.Error(t, err)
		})
	}
}
