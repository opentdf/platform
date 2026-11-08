package sdk

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRSAKeys returns RSA keys shared by the tests in this file: [0] is the
// authorized signer, [1] an unrelated signer, [2] another unrelated key.
var testRSAKeys = sync.OnceValue(func() [3]*rsa.PrivateKey {
	var keys [3]*rsa.PrivateKey
	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[i] = k
	}
	return keys
})

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rs256Signer(k *rsa.PrivateKey) func([]byte) []byte {
	return func(input []byte) []byte {
		digest := sha256.Sum256(input)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
}

func hs256Signer(secret []byte) func([]byte) []byte {
	return func(input []byte) []byte {
		mac := hmac.New(sha256.New, secret)
		mac.Write(input)
		return mac.Sum(nil)
	}
}

// compactJWS builds a JWS compact serialization from a header and payload,
// either of which may be a raw string, without any JOSE library.
func compactJWS(t *testing.T, header, payload any, sign func([]byte) []byte) string {
	t.Helper()
	enc := func(v any) []byte {
		if s, ok := v.(string); ok {
			return []byte(s)
		}
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return b
	}
	input := b64url(enc(header)) + "." + b64url(enc(payload))
	return input + "." + b64url(sign([]byte(input)))
}

func publicJWK(t *testing.T, k *rsa.PrivateKey) json.RawMessage {
	t.Helper()
	key, err := jwk.FromRaw(&k.PublicKey)
	require.NoError(t, err)
	b, err := json.Marshal(key)
	require.NoError(t, err)
	return b
}

func selfSignedX5C(t *testing.T, k *rsa.PrivateKey) []string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "assertion signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	return []string{base64.StdEncoding.EncodeToString(der)}
}

// paddedX5CLeaf returns a self-signed certificate for k whose base64 ends in
// padding, so that it has unused trailing bits.
func paddedX5CLeaf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	for cn := "assertion signer"; ; cn += "x" {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		require.NoError(t, err)
		if len(der)%3 != 0 {
			return base64.StdEncoding.EncodeToString(der)
		}
	}
}

// withStdTrailingBits sets the unused bits before the padding of a padded
// standard base64 string, which a lenient decoder ignores.
func withStdTrailingBits(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	padding := len(s) - len(strings.TrimRight(s, "="))
	mask := map[int]int{1: 0x03, 2: 0x0F}[padding]
	require.NotZero(t, mask, "no trailing bits in %q", s)
	i := len(s) - padding - 1
	return s[:i] + string(alphabet[strings.IndexByte(alphabet, s[i])|mask]) + s[i+1:]
}

// ecJWKAndX5C returns jwk and x5c headers for one P-256 key, which agree
// with each other but not with any RSA key.
func ecJWKAndX5C(t *testing.T) map[string]any {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(&k.PublicKey)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ec signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	return map[string]any{"jwk": pub, "x5c": []string{base64.StdEncoding.EncodeToString(der)}}
}

func withBinding(body, binding string) string {
	return strings.TrimSuffix(body, "}") + `,"binding":` + binding + `}`
}

// bindAssertion signs body, an assertion without a binding, for aggregate,
// and returns it with a JWS binding attached. Members of header replace the
// default {"alg": alg}; a nil value removes the member.
func bindAssertion(t *testing.T, body string, aggregate []byte, alg string, sign func([]byte) []byte, header map[string]any) string {
	t.Helper()
	hash, err := ComputeAssertionHash([]byte(body))
	require.NoError(t, err)
	sig, err := assertionSigFor(aggregate, hash, false)
	require.NoError(t, err)
	h := map[string]any{"alg": alg}
	for k, v := range header {
		if v == nil {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	jws := compactJWS(t, h, map[string]string{kAssertionHash: hash, kAssertionSignature: sig}, sign)
	return withBinding(body, `{"method":"jws","signature":"`+jws+`"}`)
}

func decodeAssertion(t *testing.T, wire string) Assertion {
	t.Helper()
	var a Assertion
	require.NoError(t, json.Unmarshal([]byte(wire), &a))
	return a
}

const (
	classificationBody = `{"id":"classification","type":"handling","scope":"payload","appliesToState":"unencrypted",` +
		`"statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":{\"cls\":\"SECRET\"}}"}}`
	changedClassificationBody = `{"id":"classification","type":"handling","scope":"payload","appliesToState":"unencrypted",` +
		`"statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":{\"cls\":\"UNCLASSIFIED\"}}"}}`
)

var (
	testAggregate  = bytes.Repeat([]byte{0xA5}, 32)
	testPayloadKey = []byte("0123456789abcdef0123456789abcdef")
)

func verifyWire(t *testing.T, keys AssertionVerificationKeys, wire string) error {
	t.Helper()
	return verifyManifestAssertion(keys, decodeAssertion(t, wire), testPayloadKey, testAggregate, false)
}

func TestAssertionEmbeddedKeysNeverAddTrust(t *testing.T) {
	keys := testRSAKeys()
	signer, other := keys[0], keys[1]
	pinned := AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey}

	perID := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": pinned}}
	byDefault := AssertionVerificationKeys{DefaultKey: pinned}

	headers := map[string]func(k *rsa.PrivateKey) map[string]any{
		"no header key": func(*rsa.PrivateKey) map[string]any { return nil },
		"jwk":           func(k *rsa.PrivateKey) map[string]any { return map[string]any{"jwk": publicJWK(t, k)} },
		"x5c":           func(k *rsa.PrivateKey) map[string]any { return map[string]any{"x5c": selfSignedX5C(t, k)} },
		"jwk and x5c": func(k *rsa.PrivateKey) map[string]any {
			return map[string]any{"jwk": publicJWK(t, k), "x5c": selfSignedX5C(t, k)}
		},
	}

	for pinName, pin := range map[string]AssertionVerificationKeys{"per-id pin": perID, "default pin": byDefault} {
		for headerName, header := range headers {
			t.Run(pinName+"/"+headerName+"/authorized signer verifies", func(t *testing.T) {
				wire := bindAssertion(t, classificationBody, testAggregate, "RS256", rs256Signer(signer), header(signer))
				require.NoError(t, verifyWire(t, pin, wire))
			})
			t.Run(pinName+"/"+headerName+"/other signer fails", func(t *testing.T) {
				wire := bindAssertion(t, changedClassificationBody, testAggregate, "RS256", rs256Signer(other), header(other))
				reason := AssertionReasonSignerNotPermitted
				if headerName == "no header key" {
					reason = AssertionReasonSignatureInvalid
				}
				requireAssertionFailure(t, verifyWire(t, pin, wire), "classification", reason)
			})
		}
	}

	t.Run("payload key mode rejects an embedded key", func(t *testing.T) {
		wire := bindAssertion(t, classificationBody, testAggregate, "HS256", hs256Signer(testPayloadKey),
			map[string]any{"jwk": publicJWK(t, other)})
		requireAssertionFailure(t, verifyWire(t, AssertionVerificationKeys{}, wire), "classification", AssertionReasonInvalidEmbeddedKey)

		control := bindAssertion(t, classificationBody, testAggregate, "HS256", hs256Signer(testPayloadKey), nil)
		require.NoError(t, verifyWire(t, AssertionVerificationKeys{}, control))
	})

	t.Run("payload key mode rejects an RS256 binding from an unrelated key", func(t *testing.T) {
		wire := bindAssertion(t, changedClassificationBody, testAggregate, "RS256", rs256Signer(other),
			map[string]any{"jwk": publicJWK(t, other)})
		requireAssertionFailure(t, verifyWire(t, AssertionVerificationKeys{}, wire), "classification", AssertionReasonAlgorithmMismatch)
	})

	t.Run("configured HMAC key rejects an embedded key", func(t *testing.T) {
		secret := []byte("shared secret for classification")
		wire := bindAssertion(t, classificationBody, testAggregate, "HS256", hs256Signer(secret),
			map[string]any{"x5c": selfSignedX5C(t, signer)})
		hmacPin := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgHS256, Key: secret}}}
		requireAssertionFailure(t, verifyWire(t, hmacPin, wire), "classification", AssertionReasonInvalidEmbeddedKey)
	})
}

func TestAssertionEmbeddedKeyChecks(t *testing.T) {
	keys := testRSAKeys()
	signer, other := keys[0], keys[1]
	pin := AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey}}
	sign := rs256Signer(signer)

	privateJWK, err := jwk.FromRaw(signer)
	require.NoError(t, err)
	privateJWKJSON, err := json.Marshal(privateJWK)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		header map[string]any
		reason AssertionFailureReason
	}{
		{"symmetric jwk", map[string]any{"jwk": map[string]string{"kty": "oct", "k": "c2VjcmV0"}}, AssertionReasonInvalidEmbeddedKey},
		{"private jwk", map[string]any{"jwk": json.RawMessage(privateJWKJSON)}, AssertionReasonInvalidEmbeddedKey},
		{"jwk without kty", map[string]any{"jwk": map[string]string{"n": "AQAB", "e": "AQAB"}}, AssertionReasonInvalidEmbeddedKey},
		{"malformed jwk", map[string]any{"jwk": map[string]string{"kty": "RSA"}}, AssertionReasonInvalidEmbeddedKey},
		{"jwk that is not an object", map[string]any{"jwk": "key"}, AssertionReasonInvalidEmbeddedKey},
		{"null jwk", map[string]any{"jwk": json.RawMessage("null")}, AssertionReasonInvalidEmbeddedKey},
		{"empty x5c", map[string]any{"x5c": []string{}}, AssertionReasonInvalidEmbeddedKey},
		{"x5c that is not an array", map[string]any{"x5c": "MIIB"}, AssertionReasonInvalidEmbeddedKey},
		{"x5c entry that is not base64", map[string]any{"x5c": []string{"not base64!"}}, AssertionReasonInvalidEmbeddedKey},
		{"x5c leaf that is not a certificate", map[string]any{"x5c": []string{"AAEC"}}, AssertionReasonInvalidEmbeddedKey},
		{"x5c entry after the leaf that is not a string", map[string]any{"x5c": []any{selfSignedX5C(t, signer)[0], 7}}, AssertionReasonInvalidEmbeddedKey},
		{"x5c leaf with a line break", map[string]any{"x5c": []string{selfSignedX5C(t, signer)[0][:40] + "\n" + selfSignedX5C(t, signer)[0][40:]}}, AssertionReasonInvalidEmbeddedKey},
		{"jwk n in the standard alphabet", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": "ab+/", "e": "AQAB"}}, AssertionReasonInvalidEmbeddedKey},
		{"jwk e padded", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": b64url(signer.N.Bytes()), "e": "AQAB="}}, AssertionReasonInvalidEmbeddedKey},
		{"jwk e empty", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": b64url(signer.N.Bytes()), "e": ""}}, AssertionReasonInvalidEmbeddedKey},
		{"jwk with only qi private", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": b64url(signer.N.Bytes()), "e": "AQAB", "qi": "AQAB"}}, AssertionReasonInvalidEmbeddedKey},
		{"matching jwk with a leading zero in n", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": b64url(append([]byte{0}, signer.N.Bytes()...)), "e": "AQAB"}}, AssertionReasonInvalidEmbeddedKey},
		{"matching jwk with a leading zero in e", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": b64url(signer.N.Bytes()), "e": "AAEAAQ"}}, AssertionReasonInvalidEmbeddedKey},
		{"matching jwk with trailing bits in n", map[string]any{"jwk": map[string]string{"kty": "RSA", "n": withTrailingBits(b64url(signer.N.Bytes())), "e": "AQAB"}}, AssertionReasonInvalidEmbeddedKey},
		{"EC jwk with a short coordinate", map[string]any{"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": b64url(bytes.Repeat([]byte{1}, 31)), "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}}, AssertionReasonInvalidEmbeddedKey},
		{"EC jwk with a padded coordinate", map[string]any{"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": b64url(append([]byte{0}, bytes.Repeat([]byte{1}, 32)...)), "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}}, AssertionReasonInvalidEmbeddedKey},
		{"EC jwk", map[string]any{"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}}, AssertionReasonSignerNotPermitted},
		{"EC jwk without y", map[string]any{"jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}}, AssertionReasonInvalidEmbeddedKey},
		{"OKP jwk without x", map[string]any{"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519"}}, AssertionReasonInvalidEmbeddedKey},
		{"jwk of an unknown kty", map[string]any{"jwk": map[string]string{"kty": "XYZ", "n": b64url(signer.N.Bytes()), "e": "AQAB"}}, AssertionReasonInvalidEmbeddedKey},
		{"OKP jwk", map[string]any{"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}, AssertionReasonSignerNotPermitted},
		{"Ed448 jwk", map[string]any{"jwk": map[string]string{"kty": "OKP", "crv": "Ed448", "x": b64url(bytes.Repeat([]byte{9}, 57))}}, AssertionReasonSignerNotPermitted},
		{"Ed25519 jwk with a short x", map[string]any{"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64url(bytes.Repeat([]byte{9}, 31))}}, AssertionReasonInvalidEmbeddedKey},
		{"X25519 jwk", map[string]any{"jwk": map[string]string{"kty": "OKP", "crv": "X25519", "x": b64url(bytes.Repeat([]byte{9}, 32))}}, AssertionReasonInvalidEmbeddedKey},
		{"EC jwk off the curve", map[string]any{"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		}}, AssertionReasonInvalidEmbeddedKey},
		{"EC jwk on an unsupported curve", map[string]any{"jwk": map[string]string{
			"kty": "EC", "crv": "secp256k1",
			"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}}, AssertionReasonInvalidEmbeddedKey},
		{"x5c leaf with trailing bits", map[string]any{"x5c": []string{withStdTrailingBits(t, paddedX5CLeaf(t, signer))}}, AssertionReasonInvalidEmbeddedKey},
		{"x5c leaf that is canonical", map[string]any{"x5c": []string{paddedX5CLeaf(t, signer)}}, ""},
		{"EC jwk and EC x5c leaf of one key", ecJWKAndX5C(t), AssertionReasonSignerNotPermitted},
		{"x5c entry after the leaf that is not base64", map[string]any{"x5c": append(selfSignedX5C(t, signer), "!!! not base64 !!!")}, AssertionReasonInvalidEmbeddedKey},
		{"x5c entry after the leaf that is unpadded", map[string]any{"x5c": append(selfSignedX5C(t, signer), "AAE")}, AssertionReasonInvalidEmbeddedKey},
		{"x5c entries after the leaf are not parsed", map[string]any{"x5c": append(selfSignedX5C(t, signer), "AAEC")}, ""},
		{"jwk and x5c disagree", map[string]any{"jwk": publicJWK(t, signer), "x5c": selfSignedX5C(t, other)}, AssertionReasonInvalidEmbeddedKey},
		{"jwk and x5c agree on another key", map[string]any{"jwk": publicJWK(t, other), "x5c": selfSignedX5C(t, other)}, AssertionReasonSignerNotPermitted},
		{"matching jwk with kid", map[string]any{"jwk": publicJWK(t, signer), "kid": "anything", "jku": "https://example.invalid/jwks"}, ""},
		{"matching x5c leaf, unvalidated chain", map[string]any{"x5c": append(selfSignedX5C(t, signer), selfSignedX5C(t, other)...)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := bindAssertion(t, classificationBody, testAggregate, "RS256", sign, tc.header)
			err := verifyWire(t, pin, wire)
			if tc.reason == "" {
				require.NoError(t, err)
				return
			}
			requireAssertionFailure(t, err, "classification", tc.reason)
		})
	}
}

func TestAssertionKeySelectionIsFinal(t *testing.T) {
	keys := testRSAKeys()
	idKey, defaultKey := keys[0], keys[1]
	idPin := AssertionKey{Alg: AssertionKeyAlgRS256, Key: &idKey.PublicKey}
	defaultPin := AssertionKey{Alg: AssertionKeyAlgRS256, Key: &defaultKey.PublicKey}

	signedByID := bindAssertion(t, classificationBody, testAggregate, "RS256", rs256Signer(idKey), nil)
	signedByDefault := bindAssertion(t, classificationBody, testAggregate, "RS256", rs256Signer(defaultKey), nil)
	signedByPayload := bindAssertion(t, classificationBody, testAggregate, "HS256", hs256Signer(testPayloadKey), nil)

	both := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": idPin}, DefaultKey: defaultPin}

	t.Run("per-id key verifies", func(t *testing.T) {
		require.NoError(t, verifyWire(t, both, signedByID))
	})
	t.Run("per-id failure does not try the default key", func(t *testing.T) {
		requireAssertionFailure(t, verifyWire(t, both, signedByDefault), "classification", AssertionReasonSignatureInvalid)
	})
	t.Run("per-id failure does not try the payload key", func(t *testing.T) {
		requireAssertionFailure(t, verifyWire(t, both, signedByPayload), "classification", AssertionReasonAlgorithmMismatch)
		hmacPin := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgHS256, Key: []byte("not the payload key")}}}
		requireAssertionFailure(t, verifyWire(t, hmacPin, signedByPayload), "classification", AssertionReasonSignatureInvalid)
	})
	t.Run("default key applies when there is no per-id key", func(t *testing.T) {
		onlyOther := AssertionVerificationKeys{Keys: map[string]AssertionKey{"other": idPin}, DefaultKey: defaultPin}
		require.NoError(t, verifyWire(t, onlyOther, signedByDefault))
		requireAssertionFailure(t, verifyWire(t, onlyOther, signedByID), "classification", AssertionReasonSignatureInvalid)
	})
	t.Run("default failure does not try the payload key", func(t *testing.T) {
		hmacDefault := AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: AssertionKeyAlgHS256, Key: []byte("not the payload key")}}
		requireAssertionFailure(t, verifyWire(t, hmacDefault, signedByPayload), "classification", AssertionReasonSignatureInvalid)
	})
	t.Run("payload key applies when nothing is configured", func(t *testing.T) {
		require.NoError(t, verifyWire(t, AssertionVerificationKeys{}, signedByPayload))
		require.NoError(t, verifyWire(t, AssertionVerificationKeys{Keys: map[string]AssertionKey{"other": idPin}}, signedByPayload))
		requireAssertionFailure(t, verifyWire(t, AssertionVerificationKeys{}, signedByID), "classification", AssertionReasonAlgorithmMismatch)
	})
	t.Run("ids match exactly", func(t *testing.T) {
		padded := "classification "
		caseDiffers := AssertionVerificationKeys{Keys: map[string]AssertionKey{"Classification": idPin, padded: idPin}}
		requireAssertionFailure(t, verifyWire(t, caseDiffers, signedByID), "classification", AssertionReasonAlgorithmMismatch)
		require.NoError(t, verifyWire(t, caseDiffers, signedByPayload))
	})

	for _, tc := range []struct {
		name string
		keys AssertionVerificationKeys
	}{
		{"empty per-id entry", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {}}, DefaultKey: defaultPin}},
		{"per-id entry without a key", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgRS256}}}},
		{"per-id entry with an unsupported algorithm", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: "ES256", Key: &idKey.PublicKey}}}},
		{"RS256 key that is a secret", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgRS256, Key: []byte("secret")}}}},
		{"RS256 key that is PEM text", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgRS256, Key: "-----BEGIN PUBLIC KEY-----"}}}},
		{"HS256 key that is an RSA public key", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgHS256, Key: &idKey.PublicKey}}}},
		{"HS256 key that is empty", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgHS256, Key: []byte{}}}}},
		{"nil RSA pointer", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgRS256, Key: (*rsa.PublicKey)(nil)}}}},
		{"default key without an algorithm", AssertionVerificationKeys{DefaultKey: AssertionKey{Key: testPayloadKey}}},
		{"default key without a key", AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: AssertionKeyAlgHS256}}},
		{"default key with only an unsupported algorithm", AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: "ES256"}}},
		{"default key with a lowercase algorithm", AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: "rs256", Key: &idKey.PublicKey}}},
		{"per-id entry with a lowercase algorithm", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: "hs256", Key: testPayloadKey}}}},
		{"HS256 key that is PEM text", AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {
			Alg: AssertionKeyAlgHS256,
			Key: []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----\n"),
		}}}},
	} {
		t.Run("configuration error: "+tc.name, func(t *testing.T) {
			requireAssertionFailure(t, verifyWire(t, tc.keys, signedByPayload), "classification", AssertionReasonConfigurationError)
			_, err := tc.keys.Get("classification")
			requireAssertionFailure(t, err, "classification", AssertionReasonConfigurationError)
		})
	}

	t.Run("accepted RS256 key forms", func(t *testing.T) {
		pubJWK, err := jwk.FromRaw(&idKey.PublicKey)
		require.NoError(t, err)
		for name, k := range map[string]any{
			"*rsa.PublicKey":  &idKey.PublicKey,
			"rsa.PublicKey":   idKey.PublicKey,
			"*rsa.PrivateKey": idKey,
			"rsa.PrivateKey":  *idKey,
			"crypto.Signer":   crypto.Signer(idKey),
			"jwk.Key":         pubJWK,
		} {
			pinned := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgRS256, Key: k}}}
			require.NoError(t, verifyWire(t, pinned, signedByID), name)
		}
	})
}

func TestAssertionJWSChecks(t *testing.T) {
	keys := testRSAKeys()
	signer := keys[0]
	rsaPin := AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey}}
	hash, err := ComputeAssertionHash([]byte(classificationBody))
	require.NoError(t, err)
	sigClaim, err := assertionSigFor(testAggregate, hash, false)
	require.NoError(t, err)
	claims := map[string]string{kAssertionHash: hash, kAssertionSignature: sigClaim}
	withJWS := func(jws string) string {
		return withBinding(classificationBody, `{"method":"jws","signature":`+string(must(json.Marshal(jws)))+`}`)
	}
	rsaSign := rs256Signer(signer)
	pubDER, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		keys   AssertionVerificationKeys
		jws    string
		reason AssertionFailureReason
	}{
		{"control", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, claims, rsaSign), ""},
		{"alg none", rsaPin, compactJWS(t, map[string]string{"alg": "none"}, claims, func([]byte) []byte { return nil }), AssertionReasonUnsupportedAlgorithm},
		{"alg missing", rsaPin, compactJWS(t, map[string]string{"typ": "JWT"}, claims, rsaSign), AssertionReasonUnsupportedAlgorithm},
		{"alg not a string", rsaPin, compactJWS(t, map[string]any{"alg": 256}, claims, rsaSign), AssertionReasonUnsupportedAlgorithm},
		{"alg unsupported", rsaPin, compactJWS(t, map[string]string{"alg": "ES256"}, claims, rsaSign), AssertionReasonUnsupportedAlgorithm},
		{"alg in another case", rsaPin, compactJWS(t, map[string]string{"alg": "rs256"}, claims, rsaSign), AssertionReasonUnsupportedAlgorithm},
		{"HS256 signed with the RSA public key", rsaPin, compactJWS(t, map[string]string{"alg": "HS256"}, claims, hs256Signer(pubDER)), AssertionReasonAlgorithmMismatch},
		{"crit", rsaPin, compactJWS(t, map[string]any{"alg": "RS256", "crit": []string{"exp"}, "exp": 1}, claims, rsaSign), AssertionReasonInvalidBinding},
		{"empty crit", rsaPin, compactJWS(t, map[string]any{"alg": "RS256", "crit": []string{}}, claims, rsaSign), AssertionReasonInvalidBinding},
		{"duplicate header member", rsaPin, compactJWS(t, `{"alg":"HS256","alg":"RS256"}`, claims, rsaSign), AssertionReasonInvalidBinding},
		{"header not JSON", rsaPin, compactJWS(t, `{alg}`, claims, rsaSign), AssertionReasonInvalidBinding},
		{"header not an object", rsaPin, compactJWS(t, `["RS256"]`, claims, rsaSign), AssertionReasonInvalidBinding},
		{"payload not an object", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, `"claims"`, rsaSign), AssertionReasonInvalidBinding},
		{"two parts", rsaPin, "eyJhbGciOiJSUzI1NiJ9.e30", AssertionReasonInvalidBinding},
		{"four parts", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, claims, rsaSign) + ".x", AssertionReasonInvalidBinding},
		{"JSON serialization", rsaPin, `{"payload":"e30","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","signature":"x"}]}`, AssertionReasonInvalidBinding},
		{"signature not base64url", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, claims, rsaSign) + "*", AssertionReasonSignatureInvalid},
		{"signature padded", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, claims, rsaSign) + "==", AssertionReasonSignatureInvalid},
		{"signature with trailing bits", rsaPin, withTrailingBits(compactJWS(t, map[string]string{"alg": "RS256"}, claims, rsaSign)), AssertionReasonSignatureInvalid},
		{"header with trailing bits", rsaPin, func() string {
			jws := compactJWS(t, map[string]string{"alg": "RS256", "x": "y"}, claims, rsaSign)
			parts := strings.SplitN(jws, ".", 2)
			return withTrailingBits(parts[0]) + "." + parts[1]
		}(), AssertionReasonInvalidBinding},
		{"header padded", rsaPin, func() string {
			jws := compactJWS(t, map[string]string{"alg": "RS256", "typ": "JWT"}, claims, rsaSign)
			parts := strings.SplitN(jws, ".", 2)
			return parts[0] + "=." + parts[1]
		}(), AssertionReasonInvalidBinding},
		{"wrong signature", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, claims, rs256Signer(keys[1])), AssertionReasonSignatureInvalid},
		{"assertionHash missing", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, map[string]string{kAssertionSignature: sigClaim}, rsaSign), AssertionReasonBindingMismatch},
		{"assertionSig not a string", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, map[string]any{kAssertionHash: hash, kAssertionSignature: 1}, rsaSign), AssertionReasonBindingMismatch},
		{"assertionHash differs", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, map[string]string{kAssertionHash: strings.ToUpper(hash), kAssertionSignature: sigClaim}, rsaSign), AssertionReasonBindingMismatch},
		{"assertionSig differs", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, map[string]string{kAssertionHash: hash, kAssertionSignature: sigClaim + "A"}, rsaSign), AssertionReasonBindingMismatch},
		{"other claims are ignored", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"}, map[string]any{
			kAssertionHash: hash, kAssertionSignature: sigClaim,
			"exp": 1, "nbf": 4102444800, "iat": 4102444800, "aud": "someone-else", "iss": "anyone",
		}, rsaSign), ""},
		{"duplicate claim", rsaPin, compactJWS(t, map[string]string{"alg": "RS256"},
			`{"assertionHash":"`+hash+`","assertionHash":"`+hash+`","assertionSig":"`+sigClaim+`"}`, rsaSign), AssertionReasonInvalidBinding},
		{"header not UTF-8", rsaPin, compactJWS(t, "{\"alg\":\"RS256\",\"x\":\"\xff\"}", claims, rsaSign), AssertionReasonInvalidBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyWire(t, tc.keys, withJWS(tc.jws))
			if tc.reason == "" {
				require.NoError(t, err)
				return
			}
			requireAssertionFailure(t, err, "classification", tc.reason)
		})
	}

	t.Run("legacy encoding is never retried", func(t *testing.T) {
		wire := withJWS(compactJWS(t, map[string]string{"alg": "RS256"}, claims, rsaSign))
		err := verifyManifestAssertion(rsaPin, decodeAssertion(t, wire), testPayloadKey, testAggregate, true)
		requireAssertionFailure(t, err, "classification", AssertionReasonBindingMismatch)

		legacySig, err := assertionSigFor(testAggregate, hash, true)
		require.NoError(t, err)
		legacyWire := withJWS(compactJWS(t, map[string]string{"alg": "RS256"}, map[string]string{kAssertionHash: hash, kAssertionSignature: legacySig}, rsaSign))
		require.NoError(t, verifyManifestAssertion(rsaPin, decodeAssertion(t, legacyWire), testPayloadKey, testAggregate, true))
		requireAssertionFailure(t, verifyManifestAssertion(rsaPin, decodeAssertion(t, legacyWire), testPayloadKey, testAggregate, false),
			"classification", AssertionReasonBindingMismatch)
	})
}

// withTrailingBits sets the unused low bits of the last character of an
// unpadded base64url string, which a lenient decoder ignores.
func withTrailingBits(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var mask int
	switch len(s) % 4 {
	case 2:
		mask = 0x0F
	case 3:
		mask = 0x03
	default:
		panic("no trailing bits in " + s)
	}
	last := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[last|mask])
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestAssertionBindingForms(t *testing.T) {
	jws := compactJWS(t, map[string]string{"alg": "HS256"}, map[string]string{
		kAssertionHash:      must(ComputeAssertionHash([]byte(classificationBody))),
		kAssertionSignature: must(assertionSigFor(testAggregate, must(ComputeAssertionHash([]byte(classificationBody))), false)),
	}, hs256Signer(testPayloadKey))
	sig := string(must(json.Marshal(jws)))

	for _, tc := range []struct {
		name    string
		binding string
		reason  AssertionFailureReason
	}{
		{"method jws", `{"method":"jws","signature":` + sig + `}`, ""},
		{"method JWS", `{"method":"JWS","signature":` + sig + `}`, ""},
		{"method missing", `{"signature":` + sig + `}`, ""},
		{"unmodelled binding member", `{"signature":` + sig + `,"note":1}`, ""},
		{"unknown method", `{"method":"jwt","signature":` + sig + `}`, AssertionReasonUnsupportedBinding},
		{"method in another case", `{"method":"Jws","signature":` + sig + `}`, AssertionReasonUnsupportedBinding},
		{"method not a string", `{"method":1,"signature":` + sig + `}`, AssertionReasonInvalidBinding},
		{"null method", `{"method":null,"signature":` + sig + `}`, AssertionReasonInvalidBinding},
		{"signature not a string", `{"method":"jws","signature":{"jws":` + sig + `}}`, AssertionReasonInvalidBinding},
		{"bdo alone", `{"bdo":"opaque"}`, AssertionReasonUnsupportedBinding},
		{"bdo with a jws method", `{"method":"jws","bdo":{"ref":"x"}}`, AssertionReasonUnsupportedBinding},
		{"bdo with a non-string method", `{"method":5,"bdo":null}`, AssertionReasonUnsupportedBinding},
		{"both forms", `{"method":"jws","signature":` + sig + `,"bdo":"opaque"}`, AssertionReasonInvalidBinding},
		{"neither form", `{"method":"jws"}`, AssertionReasonInvalidBinding},
		{"empty binding", `{}`, AssertionReasonInvalidBinding},
		{"binding not an object", `"` + jws + `"`, AssertionReasonInvalidBinding},
		{"null binding", `null`, AssertionReasonInvalidBinding},
		{"empty signature", `{"signature":""}`, AssertionReasonInvalidBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyWire(t, AssertionVerificationKeys{}, withBinding(classificationBody, tc.binding))
			if tc.reason == "" {
				require.NoError(t, err)
				return
			}
			requireAssertionFailure(t, err, "classification", tc.reason)
		})
	}

	t.Run("no binding", func(t *testing.T) {
		requireAssertionFailure(t, verifyWire(t, AssertionVerificationKeys{}, classificationBody), "classification", AssertionReasonInvalidBinding)
	})
}

func TestAssertionInvalidID(t *testing.T) {
	// The id is checked before the key is selected, so even an unusable
	// configuration reports invalid-id.
	broken := AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: "ES256"}}
	for _, body := range []string{
		`{"type":"other","scope":"tdo","statement":{"value":"v"}}`,
		`{"id":"","type":"other"}`,
		`{"id":null,"type":"other"}`,
		`{"id":7,"type":"other"}`,
		`{"id":["a"],"type":"other"}`,
	} {
		t.Run(body, func(t *testing.T) {
			wire := withBinding(body, `{"signature":"a.b.c"}`)
			requireAssertionFailure(t, verifyWire(t, broken, wire), "", AssertionReasonInvalidID)
		})
	}

	t.Run("null assertion", func(t *testing.T) {
		var list []Assertion
		require.NoError(t, json.Unmarshal([]byte(`[null]`), &list))
		err := verifyManifestAssertion(AssertionVerificationKeys{}, list[0], testPayloadKey, testAggregate, false)
		requireAssertionFailure(t, err, "", AssertionReasonInvalidID)
	})

	t.Run("id with spaces and escapes is kept exactly", func(t *testing.T) {
		body := `{"id":" classification ","type":"other"}`
		key := []byte("exact id key")
		wire := bindAssertion(t, body, testAggregate, "HS256", hs256Signer(key), nil)
		exact := AssertionVerificationKeys{Keys: map[string]AssertionKey{" classification ": {Alg: AssertionKeyAlgHS256, Key: key}}}
		require.NoError(t, verifyWire(t, exact, wire))
		trimmed := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": {Alg: AssertionKeyAlgHS256, Key: key}}}
		requireAssertionFailure(t, verifyWire(t, trimmed, wire), " classification ", AssertionReasonSignatureInvalid)
	})
}

func TestAssertionUnmodelledMembersAreAuthenticated(t *testing.T) {
	signer := testRSAKeys()[0]
	pin := AssertionVerificationKeys{DefaultKey: AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey}}
	body := strings.TrimSuffix(classificationBody, "}") + `,"extensions":{"hash":"deadbeef","note":"coi"}}`
	wire := bindAssertion(t, body, testAggregate, "RS256", rs256Signer(signer), nil)
	require.NoError(t, verifyWire(t, pin, wire))

	for name, tampered := range map[string]string{
		"changed":  strings.Replace(wire, `"note":"coi"`, `"note":"none"`, 1),
		"removed":  strings.Replace(wire, `,"extensions":{"hash":"deadbeef","note":"coi"}`, ``, 1),
		"added":    strings.Replace(wire, `"id":"classification",`, `"id":"classification","releasableTo":"all",`, 1),
		"in value": strings.Replace(wire, `SECRET`, `UNCLASSIFIED`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, wire, tampered)
			requireAssertionFailure(t, verifyWire(t, pin, tampered), "classification", AssertionReasonBindingMismatch)
		})
	}
}

func TestAssertionVerifyUsesOnlyTheGivenKey(t *testing.T) {
	keys := testRSAKeys()
	signer, other := keys[0], keys[1]

	// An RS256 binding from an unrelated key that carries that key as a jwk.
	unrelated := bindAssertion(t, changedClassificationBody, testAggregate, "RS256", rs256Signer(other),
		map[string]any{"jwk": publicJWK(t, other)})
	_, _, err := decodeAssertion(t, unrelated).Verify(AssertionKey{Alg: AssertionKeyAlgHS256, Key: []byte("dummy payload key")})
	requireAssertionFailure(t, err, "classification", AssertionReasonAlgorithmMismatch)

	_, _, err = decodeAssertion(t, unrelated).Verify(AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey})
	requireAssertionFailure(t, err, "classification", AssertionReasonSignerNotPermitted)

	authorized := bindAssertion(t, classificationBody, testAggregate, "RS256", rs256Signer(signer),
		map[string]any{"jwk": publicJWK(t, signer)})
	hash, sig, err := decodeAssertion(t, authorized).Verify(AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey})
	require.NoError(t, err)
	wantHash, err := ComputeAssertionHash([]byte(classificationBody))
	require.NoError(t, err)
	assert.Equal(t, wantHash, hash)
	assert.Equal(t, must(assertionSigFor(testAggregate, wantHash, false)), sig)

	_, _, err = decodeAssertion(t, authorized).Verify(AssertionKey{Alg: AssertionKeyAlgRS256})
	requireAssertionFailure(t, err, "classification", AssertionReasonConfigurationError)
}

// rewriteTDFManifest returns a copy of the TDF archive tdf with its manifest
// replaced by change(manifest).
func rewriteTDFManifest(t *testing.T, tdf []byte, change func(manifest []byte) []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(tdf), int64(len(tdf)))
	require.NoError(t, err)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		if f.Name == "0.manifest.json" {
			body = change(body)
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Store})
		require.NoError(t, err)
		_, err = w.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return out.Bytes()
}

// manifestAggregate returns the aggregate segment hash of a manifest, which
// anyone holding the TDF can compute.
func manifestAggregate(t *testing.T, manifest []byte) []byte {
	t.Helper()
	var m Manifest
	require.NoError(t, json.Unmarshal(manifest, &m))
	var agg []byte
	for _, seg := range m.Segments {
		h, err := ocrypto.Base64Decode([]byte(seg.Hash))
		require.NoError(t, err)
		agg = append(agg, h...)
	}
	return agg
}

// setManifestAssertions replaces the manifest's assertions with list, keeping
// every other member as it was.
func setManifestAssertions(t *testing.T, manifest []byte, list []json.RawMessage) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(manifest, &top))
	encoded, err := json.Marshal(list)
	require.NoError(t, err)
	top["assertions"] = encoded
	out, err := json.Marshal(top)
	require.NoError(t, err)
	return out
}

func manifestAssertions(t *testing.T, manifest []byte) []json.RawMessage {
	t.Helper()
	var top struct {
		Assertions []json.RawMessage `json:"assertions"`
	}
	require.NoError(t, json.Unmarshal(manifest, &top))
	return top.Assertions
}

// Test_TDFAssertionPinning checks, end to end through the reader, that an
// assertion appended to or replacing one in a TDF verifies only under the
// key the reader configured, whatever key it embeds.
func (s *TDFSuite) Test_TDFAssertionPinning() {
	t := s.T()
	keys := testRSAKeys()
	signer, other := keys[0], keys[1]
	pinned := AssertionKey{Alg: AssertionKeyAlgRS256, Key: &signer.PublicKey}

	var tdf bytes.Buffer
	_, err := s.sdk.CreateTDF(&tdf, strings.NewReader("pinned plaintext"),
		WithKasInformation(s.kases[0].KASInfo),
		WithAutoconfigure(false),
		WithAssertions(AssertionConfig{
			ID:             "classification",
			Type:           HandlingAssertion,
			Scope:          PayloadScope,
			AppliesToState: Unencrypted,
			Statement:      Statement{Format: "json+stanag5636", Schema: "urn:nato:stanag:5636:A:1:elements:json", Value: `{"ocl":{"cls":"SECRET"}}`},
			SigningKey:     AssertionKey{Alg: AssertionKeyAlgRS256, Key: signer},
		}))
	s.Require().NoError(err)

	read := func(data []byte, verifiers AssertionVerificationKeys) error {
		r, err := s.sdk.LoadTDF(bytes.NewReader(data), WithAssertionVerificationKeys(verifiers))
		if err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, r)
		return err
	}

	perID := AssertionVerificationKeys{Keys: map[string]AssertionKey{"classification": pinned}}
	byDefault := AssertionVerificationKeys{DefaultKey: pinned}

	s.Run("unmodified TDF verifies under each pin", func() {
		s.Require().NoError(read(tdf.Bytes(), perID))
		s.Require().NoError(read(tdf.Bytes(), byDefault))
	})

	embedded := map[string]func(k *rsa.PrivateKey) map[string]any{
		"jwk": func(k *rsa.PrivateKey) map[string]any { return map[string]any{"jwk": publicJWK(t, k)} },
		"x5c": func(k *rsa.PrivateKey) map[string]any { return map[string]any{"x5c": selfSignedX5C(t, k)} },
	}
	for name, header := range embedded {
		resign := func(body string, k *rsa.PrivateKey, replace bool) []byte {
			return rewriteTDFManifest(t, tdf.Bytes(), func(manifest []byte) []byte {
				wire := bindAssertion(t, body, manifestAggregate(t, manifest), "RS256", rs256Signer(k), header(k))
				list := manifestAssertions(t, manifest)
				if replace {
					list = nil
				}
				return setManifestAssertions(t, manifest, append(list, json.RawMessage(wire)))
			})
		}
		appendedBody := strings.Replace(changedClassificationBody, `"id":"classification"`, `"id":"classification-extra"`, 1)

		s.Run(name+"/replaced assertion from an unrelated key fails under each pin", func() {
			replaced := resign(changedClassificationBody, other, true)
			requireAssertionFailure(t, read(replaced, perID), "classification", AssertionReasonSignerNotPermitted)
			requireAssertionFailure(t, read(replaced, byDefault), "classification", AssertionReasonSignerNotPermitted)
		})
		s.Run(name+"/added assertion from an unrelated key fails", func() {
			appended := resign(appendedBody, other, false)
			requireAssertionFailure(t, read(appended, byDefault), "classification-extra", AssertionReasonSignerNotPermitted)
			// Under a per-id pin, an unlisted id falls to the payload key, so
			// an RS256 binding cannot verify at all.
			requireAssertionFailure(t, read(appended, perID), "classification-extra", AssertionReasonAlgorithmMismatch)
		})
		s.Run(name+"/added assertion from the authorized signer verifies", func() {
			s.Require().NoError(read(resign(appendedBody, signer, false), byDefault))
		})
	}
}
