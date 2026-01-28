package security

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandardCryptoKeyLookup(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)

	kids, err := cryptoProvider.ListKIDsByAlgorithm(AlgorithmRSA2048)
	require.NoError(t, err)
	require.Len(t, kids, 1)
	assert.Equal(t, material.rsaKid, kids[0])

	_, err = cryptoProvider.ListKIDsByAlgorithm("nope")
	require.ErrorIs(t, err, ErrCertNotFound)

	found := cryptoProvider.FindKID(AlgorithmRSA2048)
	assert.Equal(t, material.rsaKid, found)
	assert.Empty(t, cryptoProvider.FindKID("missing"))
}

func TestStandardCryptoPublicKeys(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)

	rsaPEM, err := cryptoProvider.RSAPublicKey(material.rsaKid)
	require.NoError(t, err)
	assert.Contains(t, rsaPEM, "PUBLIC KEY")

	rsaJSON, err := cryptoProvider.RSAPublicKeyAsJSON(material.rsaKid)
	require.NoError(t, err)
	assert.True(t, json.Valid([]byte(rsaJSON)))

	ecCert, err := cryptoProvider.ECCertificate(material.ecKid)
	require.NoError(t, err)
	assert.Equal(t, material.ecPublicPEM, ecCert)

	ecPEM, err := cryptoProvider.ECPublicKey(material.ecKid)
	require.NoError(t, err)
	assert.Contains(t, ecPEM, "PUBLIC KEY")
}

func TestStandardCryptoDecrypt(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)

	t.Run("rsa decrypt", func(t *testing.T) {
		key, ok := cryptoProvider.keysByID[material.rsaKid].(StandardRSACrypto)
		require.True(t, ok)
		rawKey := make([]byte, 32)
		_, err := rand.Read(rawKey)
		require.NoError(t, err)
		ciphertext, err := key.asymEncryption.Encrypt(rawKey)
		require.NoError(t, err)

		protected, err := cryptoProvider.Decrypt(t.Context(), trust.KeyIdentifier(material.rsaKid), ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, rawKey, exportProtectedKey(t, protected))
	})

	t.Run("ec decrypt", func(t *testing.T) {
		rawKey := make([]byte, 32)
		_, err := rand.Read(rawKey)
		require.NoError(t, err)
		encryptor, err := ocrypto.FromPublicPEMWithSalt(material.ecPublicPEM, TDFSalt(), nil)
		require.NoError(t, err)

		ciphertext, err := encryptor.Encrypt(rawKey)
		require.NoError(t, err)

		protected, err := cryptoProvider.Decrypt(t.Context(), trust.KeyIdentifier(material.ecKid), ciphertext, encryptor.EphemeralKey())
		require.NoError(t, err)
		assert.Equal(t, rawKey, exportProtectedKey(t, protected))
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := cryptoProvider.Decrypt(t.Context(), trust.KeyIdentifier("missing"), nil, nil)
		require.Error(t, err)
	})

	t.Run("rsa with ephemeral key", func(t *testing.T) {
		key, ok := cryptoProvider.keysByID[material.rsaKid].(StandardRSACrypto)
		require.True(t, ok)
		rawKey := []byte("rsa-secret")
		ciphertext, err := key.asymEncryption.Encrypt(rawKey)
		require.NoError(t, err)

		_, err = cryptoProvider.Decrypt(t.Context(), trust.KeyIdentifier(material.rsaKid), ciphertext, []byte("nope"))
		require.Error(t, err)
	})

	t.Run("ec without ephemeral key", func(t *testing.T) {
		rawKey := []byte("ec-secret")
		encryptor, err := ocrypto.FromPublicPEMWithSalt(material.ecPublicPEM, TDFSalt(), nil)
		require.NoError(t, err)

		ciphertext, err := encryptor.Encrypt(rawKey)
		require.NoError(t, err)

		_, err = cryptoProvider.Decrypt(t.Context(), trust.KeyIdentifier(material.ecKid), ciphertext, nil)
		require.Error(t, err)
	})
}

func TestStandardCryptoLoadErrors(t *testing.T) {
	dir := t.TempDir()
	privatePath := writeTempFile(t, dir, "key.pem", "test")

	t.Run("duplicate kid", func(t *testing.T) {
		cfg := StandardConfig{
			Keys: []KeyPairInfo{
				{Algorithm: AlgorithmRSA2048, KID: "dup", Private: privatePath, Certificate: privatePath},
				{Algorithm: AlgorithmRSA2048, KID: "dup", Private: privatePath, Certificate: privatePath},
			},
		}
		_, err := NewStandardCrypto(cfg)
		require.Error(t, err)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		cfg := StandardConfig{
			Keys: []KeyPairInfo{
				{Algorithm: "unsupported", KID: "kid", Private: privatePath, Certificate: privatePath},
			},
		}
		_, err := NewStandardCrypto(cfg)
		require.Error(t, err)
	})

	t.Run("mixed new and deprecated config", func(t *testing.T) {
		cfg := StandardConfig{
			Keys:    []KeyPairInfo{{Algorithm: AlgorithmRSA2048, KID: "kid", Private: privatePath, Certificate: privatePath}},
			RSAKeys: map[string]StandardKeyInfo{"legacy": {PrivateKeyPath: privatePath, PublicKeyPath: privatePath}},
		}
		_, err := NewStandardCrypto(cfg)
		require.Error(t, err)
	})
}

func TestStandardCryptoDeprecatedKeys(t *testing.T) {
	dir := t.TempDir()

	rsaPair, err := generateRSAKeyAndPEM()
	require.NoError(t, err)
	rsaPrivatePEM, err := rsaPair.PrivateKeyInPemFormat()
	require.NoError(t, err)
	rsaPublicPEM, err := rsaPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	ecPair, err := generateECKeyAndPEM(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	ecPrivatePEM, err := ecPair.PrivateKeyInPemFormat()
	require.NoError(t, err)
	ecPublicPEM, err := ecPair.PublicKeyInPemFormat()
	require.NoError(t, err)

	rsaPrivatePath := writeTempFile(t, dir, "rsa-private.pem", rsaPrivatePEM)
	rsaPublicPath := writeTempFile(t, dir, "rsa-public.pem", rsaPublicPEM)
	ecPrivatePath := writeTempFile(t, dir, "ec-private.pem", ecPrivatePEM)
	ecPublicPath := writeTempFile(t, dir, "ec-public.pem", ecPublicPEM)

	cfg := StandardConfig{
		RSAKeys: map[string]StandardKeyInfo{
			"rsa-legacy": {PrivateKeyPath: rsaPrivatePath, PublicKeyPath: rsaPublicPath},
		},
		ECKeys: map[string]StandardKeyInfo{
			"ec-legacy": {PrivateKeyPath: ecPrivatePath, PublicKeyPath: ecPublicPath},
		},
	}

	cryptoProvider, err := NewStandardCrypto(cfg)
	require.NoError(t, err)

	rsaKids, err := cryptoProvider.ListKIDsByAlgorithm(AlgorithmRSA2048)
	require.NoError(t, err)
	assert.Equal(t, []string{"rsa-legacy"}, rsaKids)

	ecKids, err := cryptoProvider.ListKIDsByAlgorithm(AlgorithmECP256R1)
	require.NoError(t, err)
	assert.Equal(t, []string{"ec-legacy"}, ecKids)
}

func TestStandardCryptoRSAPublicKeyErrors(t *testing.T) {
	cryptoProvider, material := newStandardCryptoForTest(t, true, true)

	_, err := cryptoProvider.RSAPublicKey("missing")
	require.ErrorIs(t, err, ErrCertNotFound)

	_, err = cryptoProvider.RSAPublicKey(material.ecKid)
	require.ErrorIs(t, err, ErrCertNotFound)
}
