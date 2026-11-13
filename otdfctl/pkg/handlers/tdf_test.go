package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zipPrefix is the signature sdk.GetTdfType looks for. It is enough to route
// input down the Standard branch, which is where the option plumbing lives; the
// cases below all fail before anything reaches the SDK, so no platform
// connection and no real TDF is needed.
var zipPrefix = []byte{0x50, 0x4B, 0x03, 0x04}

func TestDecryptRejectsNonTDFInput(t *testing.T) {
	var out bytes.Buffer

	err := Handler{}.Decrypt(t.Context(), &out, bytes.NewReader([]byte("not a tdf at all")), DecryptOptions{})

	require.EqualError(t, err, "invalid TDF")
	assert.Empty(t, out.Bytes(), "a rejected input must not produce output")
}

// GetTdfType cannot read four bytes from an empty input, so it reports Invalid
// rather than a read error. Worth pinning: an empty spool is a plausible way to
// get here, and "invalid TDF" is the message the user sees for it.
func TestDecryptRejectsEmptyInput(t *testing.T) {
	var out bytes.Buffer

	err := Handler{}.Decrypt(t.Context(), &out, bytes.NewReader(nil), DecryptOptions{})

	require.EqualError(t, err, "invalid TDF")
	assert.Empty(t, out.Bytes())
}

func TestDecryptAssertionVerificationKeyErrors(t *testing.T) {
	dir := t.TempDir()

	malformed := filepath.Join(dir, "malformed.json")
	require.NoError(t, os.WriteFile(malformed, []byte("{not json"), 0o600))

	badKey := filepath.Join(dir, "bad-key.json")
	require.NoError(t, os.WriteFile(badKey,
		[]byte(`{"keys":{"assertion1":{"alg":"RS256","key":"not a pem block"}}}`), 0o600))

	for _, tc := range []struct {
		name    string
		file    string
		wantMsg string
	}{
		{
			name:    "missing file",
			file:    filepath.Join(dir, "does-not-exist.json"),
			wantMsg: "unable to read assertions verification keys file",
		},
		{
			name:    "malformed json",
			file:    malformed,
			wantMsg: "unable to unmarshal assertion verification keys json",
		},
		{
			name:    "unusable key",
			file:    badKey,
			wantMsg: `error with assertion verification key for "assertion1", reason=configuration-error`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer

			err := Handler{}.Decrypt(t.Context(), &out, bytes.NewReader(zipPrefix), DecryptOptions{
				AssertionVerificationKeysFile: tc.file,
			})

			require.ErrorContains(t, err, tc.wantMsg)
			assert.Empty(t, out.Bytes(), "an option failure must not produce output")
		})
	}
}

// An unset SessionKeyAlgorithm must mean "let the SDK choose", not "use the
// empty algorithm". The empty string is not a valid ocrypto.KeyType, so passing
// it through to WithSessionKeyType fails config construction before the TDF is
// ever read — a trap the CLI only avoids because it happens to fill the field
// in. Reaching the zip reader (rather than a key-type error) is what proves the
// option was skipped.
func TestDecryptDefaultsSessionKeyAlgorithm(t *testing.T) {
	var out bytes.Buffer

	h := Handler{sdk: &sdk.SDK{}}
	err := h.Decrypt(t.Context(), &out, bytes.NewReader(zipPrefix), DecryptOptions{})

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unsupported key type",
		"an unset session key algorithm must fall through to the SDK default")
}

func TestInspectTDFRejectsNonTDFInput(t *testing.T) {
	result, errs := Handler{}.InspectTDF(bytes.NewReader([]byte("not a tdf at all")))

	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], ErrTDFInspectFailNotValidTDF)
	assert.Nil(t, result.ZTDFManifest)
}

func writeKeysFile(t *testing.T, contents any) string {
	t.Helper()
	data, err := json.Marshal(contents)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "keys.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// requireVerifies signs an assertion with signing and checks that the SDK
// verifies its binding with verification.
func requireVerifies(t *testing.T, signing, verification sdk.AssertionKey) {
	t.Helper()
	a := sdk.Assertion{ID: "assertion2", Type: sdk.BaseAssertion, Scope: sdk.PayloadScope, Statement: sdk.Statement{Value: "v"}}
	require.NoError(t, a.Sign("hash", "sig", signing))
	hash, sig, err := a.Verify(verification)
	require.NoError(t, err)
	assert.Equal(t, "hash", hash)
	assert.Equal(t, "sig", sig)
}

func TestReadAssertionVerificationKeysDefaultKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

	t.Run("HS256 default key", func(t *testing.T) {
		keys, err := readAssertionVerificationKeys(writeKeysFile(t, map[string]any{
			"defaultKey": map[string]string{"alg": "HS256", "key": "k0cn4xBcY+49z5gs4OHUs/kbQ3/T8p+uUW9pIQ/9aqE="},
		}))
		require.NoError(t, err)
		assert.Equal(t, sdk.AssertionKey{Alg: sdk.AssertionKeyAlgHS256, Key: []byte("k0cn4xBcY+49z5gs4OHUs/kbQ3/T8p+uUW9pIQ/9aqE=")}, keys.DefaultKey)
		assert.Empty(t, keys.Keys)
		selected, err := keys.Get("any-id")
		require.NoError(t, err, "the SDK must accept the converted default key")
		assert.Equal(t, keys.DefaultKey, selected)
		requireVerifies(t, sdk.AssertionKey{Alg: sdk.AssertionKeyAlgHS256, Key: []byte("k0cn4xBcY+49z5gs4OHUs/kbQ3/T8p+uUW9pIQ/9aqE=")}, selected)
	})

	t.Run("RS256 default key alongside per-id keys", func(t *testing.T) {
		keys, err := readAssertionVerificationKeys(writeKeysFile(t, map[string]any{
			"keys":       map[string]any{"assertion1": map[string]string{"alg": "HS256", "key": "secret"}},
			"defaultKey": map[string]string{"alg": "RS256", "key": publicPEM},
		}))
		require.NoError(t, err)
		assert.Equal(t, sdk.AssertionKeyAlgRS256, keys.DefaultKey.Alg)
		pub, ok := keys.DefaultKey.Key.(*rsa.PublicKey)
		require.True(t, ok, "default key is %T", keys.DefaultKey.Key)
		assert.True(t, pub.Equal(&rsaKey.PublicKey))
		assert.Equal(t, sdk.AssertionKey{Alg: sdk.AssertionKeyAlgHS256, Key: []byte("secret")}, keys.Keys["assertion1"])

		selected, err := keys.Get("assertion2")
		require.NoError(t, err)
		assert.Equal(t, keys.DefaultKey, selected)
		requireVerifies(t, sdk.AssertionKey{Alg: sdk.AssertionKeyAlgRS256, Key: rsaKey}, selected)
		selected, err = keys.Get("assertion1")
		require.NoError(t, err)
		assert.Equal(t, keys.Keys["assertion1"], selected)
	})

	t.Run("no default key", func(t *testing.T) {
		keys, err := readAssertionVerificationKeys(writeKeysFile(t, map[string]any{
			"keys": map[string]any{"assertion1": map[string]string{"alg": "RS256", "key": publicPEM}},
		}))
		require.NoError(t, err)
		assert.True(t, keys.DefaultKey.IsEmpty())
		selected, err := keys.Get("unlisted")
		require.NoError(t, err)
		assert.True(t, selected.IsEmpty(), "an unlisted id falls to the payload key")
	})

	for name, defaultKey := range map[string]any{
		"unparsable RS256 key":          map[string]string{"alg": "RS256", "key": "not a pem block"},
		"malformed RSA private key":     map[string]string{"alg": "RS256", "key": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}))},
		"missing algorithm":             map[string]string{"key": "secret"},
		"unsupported algorithm":         map[string]string{"alg": "ES256", "key": publicPEM},
		"missing key":                   map[string]string{"alg": "HS256"},
		"key that is not a JSON string": map[string]any{"alg": "HS256", "key": 7},
		"HS256 key that is PEM text":    map[string]string{"alg": "HS256", "key": publicPEM},
		"lowercase algorithm":           map[string]string{"alg": "rs256", "key": publicPEM},
		"unsupported algorithm alone":   map[string]string{"alg": "ES256"},
	} {
		t.Run("invalid default key: "+name, func(t *testing.T) {
			path := writeKeysFile(t, map[string]any{"defaultKey": defaultKey})
			_, err := readAssertionVerificationKeys(path)
			require.ErrorContains(t, err, "reason=configuration-error")

			var out bytes.Buffer
			err = Handler{}.Decrypt(t.Context(), &out, bytes.NewReader(zipPrefix), DecryptOptions{AssertionVerificationKeysFile: path})
			require.ErrorContains(t, err, "default assertion verification key, reason=configuration-error")
			assert.Empty(t, out.Bytes())
		})
	}
}

func TestReadAssertionVerificationKeysMembers(t *testing.T) {
	entry := map[string]string{"alg": "HS256", "key": "secret"}

	for name, contents := range map[string]any{
		"misspelled default key": map[string]any{"default_key": entry},
		"unknown member":         map[string]any{"keys": map[string]any{}, "extra": true},
		"both spellings":         map[string]any{"defaultKey": entry, "DefaultKey": entry},
		"HS256 per-id key that is PEM text": map[string]any{"keys": map[string]any{
			"a": map[string]string{"alg": "HS256", "key": "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"},
		}},
		"empty per-id entry": map[string]any{"keys": map[string]any{"x": map[string]any{}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readAssertionVerificationKeys(writeKeysFile(t, contents))
			require.ErrorContains(t, err, "reason=configuration-error")
		})
	}

	for name, contents := range map[string]any{
		"defaultKey":       map[string]any{"defaultKey": entry},
		"DefaultKey":       map[string]any{"DefaultKey": entry},
		"Keys":             map[string]any{"Keys": map[string]any{"a": entry}},
		"empty defaultKey": map[string]any{"defaultKey": map[string]any{}},
		"empty file":       map[string]any{},
	} {
		t.Run("accepted: "+name, func(t *testing.T) {
			keys, err := readAssertionVerificationKeys(writeKeysFile(t, contents))
			require.NoError(t, err)
			if name == "empty defaultKey" || name == "empty file" {
				assert.True(t, keys.DefaultKey.IsEmpty(), "an empty defaultKey is absent, not invalid")
			}
		})
	}
}
