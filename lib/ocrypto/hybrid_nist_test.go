package ocrypto

import (
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestP256MLKEM768KeyPairAndPEM(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	// Public/private PEMs round-trip via the OID-routed dispatcher.
	enc, err := FromPublicPEM(publicPEM)
	require.NoError(t, err)
	dec, err := FromPrivatePEM(privatePEM)
	require.NoError(t, err)

	wrapped, err := enc.Encrypt([]byte("round-trip"))
	require.NoError(t, err)
	plaintext, err := dec.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("round-trip"), plaintext)

	assert.Len(t, keyPair.publicKey, P256MLKEM768PublicKeySize)
	assert.Equal(t, HybridSecp256r1MLKEM768Key, keyPair.GetKeyType())
}

func TestP384MLKEM1024KeyPairAndPEM(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	enc, err := FromPublicPEM(publicPEM)
	require.NoError(t, err)
	dec, err := FromPrivatePEM(privatePEM)
	require.NoError(t, err)

	wrapped, err := enc.Encrypt([]byte("round-trip-384"))
	require.NoError(t, err)
	plaintext, err := dec.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("round-trip-384"), plaintext)

	assert.Len(t, keyPair.publicKey, P384MLKEM1024PublicKeySize)
	assert.Equal(t, HybridSecp384r1MLKEM1024Key, keyPair.GetKeyType())
}

func TestNewKeyPairP256MLKEM768(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)
	assert.Equal(t, HybridSecp256r1MLKEM768Key, keyPair.GetKeyType())
}

func TestNewKeyPairP384MLKEM1024(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)
	assert.Equal(t, HybridSecp384r1MLKEM1024Key, keyPair.GetKeyType())
}

func TestP256MLKEM768WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := P256MLKEM768WrapDEK(keyPair.publicKey, dek)
	require.NoError(t, err)

	plaintext, err := P256MLKEM768UnwrapDEK(keyPair.privateKey, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestP384MLKEM1024WrapUnwrapRoundTrip(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := P384MLKEM1024WrapDEK(keyPair.publicKey, dek)
	require.NoError(t, err)

	plaintext, err := P384MLKEM1024UnwrapDEK(keyPair.privateKey, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, plaintext)
}

func TestP256MLKEM768WrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)
	wrongKeyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	wrapped, err := P256MLKEM768WrapDEK(keyPair.publicKey, []byte("top secret dek"))
	require.NoError(t, err)

	_, err = P256MLKEM768UnwrapDEK(wrongKeyPair.privateKey, wrapped)
	require.Error(t, err)
	// Wrong-key failure must surface through AES-GCM authentication, not a
	// parse/size mismatch — ML-KEM uses implicit rejection so DecapsulateTo
	// returns a pseudorandom secret rather than an error.
	assert.ErrorContains(t, err, "AES-GCM decrypt failed")
}

func TestP384MLKEM1024WrapUnwrapWrongKeyFails(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)
	wrongKeyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	wrapped, err := P384MLKEM1024WrapDEK(keyPair.publicKey, []byte("top secret dek"))
	require.NoError(t, err)

	_, err = P384MLKEM1024UnwrapDEK(wrongKeyPair.privateKey, wrapped)
	require.Error(t, err)
	assert.ErrorContains(t, err, "AES-GCM decrypt failed")
}

func TestHybridNISTWrappedKeyASN1RoundTrip(t *testing.T) {
	original := HybridNISTWrappedKey{
		HybridCiphertext: []byte("hybrid-ciphertext-data"),
		EncryptedDEK:     []byte("encrypted-dek-data"),
	}

	der, err := asn1.Marshal(original)
	require.NoError(t, err)

	var decoded HybridNISTWrappedKey
	rest, err := asn1.Unmarshal(der, &decoded)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, original, decoded)
}

func TestP256MLKEM768PEMDispatch(t *testing.T) {
	keyPair, err := NewP256MLKEM768KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	encryptor, err := FromPublicPEM(publicPEM)
	require.NoError(t, err)

	decryptor, err := FromPrivatePEM(privatePEM)
	require.NoError(t, err)

	nistEncryptor, ok := encryptor.(*HybridNISTEncryptor)
	require.True(t, ok)
	assert.Equal(t, Hybrid, nistEncryptor.Type())
	assert.Equal(t, HybridSecp256r1MLKEM768Key, nistEncryptor.KeyType())
	assert.Nil(t, nistEncryptor.EphemeralKey())

	metadata, err := nistEncryptor.Metadata()
	require.NoError(t, err)
	assert.Empty(t, metadata)

	nistDecryptor, ok := decryptor.(*HybridNISTDecryptor)
	require.True(t, ok)

	wrapped, err := nistEncryptor.Encrypt([]byte("dispatch-dek"))
	require.NoError(t, err)

	plaintext, err := nistDecryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("dispatch-dek"), plaintext)
}

func TestP384MLKEM1024PEMDispatch(t *testing.T) {
	keyPair, err := NewP384MLKEM1024KeyPair()
	require.NoError(t, err)

	publicPEM, err := keyPair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privatePEM, err := keyPair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	encryptor, err := FromPublicPEM(publicPEM)
	require.NoError(t, err)

	decryptor, err := FromPrivatePEM(privatePEM)
	require.NoError(t, err)

	nistEncryptor, ok := encryptor.(*HybridNISTEncryptor)
	require.True(t, ok)
	assert.Equal(t, Hybrid, nistEncryptor.Type())
	assert.Equal(t, HybridSecp384r1MLKEM1024Key, nistEncryptor.KeyType())
	assert.Nil(t, nistEncryptor.EphemeralKey())

	nistDecryptor, ok := decryptor.(*HybridNISTDecryptor)
	require.True(t, ok)

	wrapped, err := nistEncryptor.Encrypt([]byte("dispatch-dek-384"))
	require.NoError(t, err)

	plaintext, err := nistDecryptor.Decrypt(wrapped)
	require.NoError(t, err)
	assert.Equal(t, []byte("dispatch-dek-384"), plaintext)
}

// TestHybridNISTPEMShape verifies that the emitted PEM blocks carry the
// expected SPKI/PKCS#8 envelope and OID per draft-ietf-lamps-pq-composite-kem-14.
func TestHybridNISTPEMShape(t *testing.T) {
	cases := []struct {
		name string
		gen  func() (HybridNISTKeyPair, error)
		oid  asn1.ObjectIdentifier
	}{
		{"P256+MLKEM768", NewP256MLKEM768KeyPair, oidCompositeMLKEM768P256},
		{"P384+MLKEM1024", NewP384MLKEM1024KeyPair, oidCompositeMLKEM1024P384},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := tc.gen()
			require.NoError(t, err)

			pubPEM, err := kp.PublicKeyInPemFormat()
			require.NoError(t, err)
			pubBlock, _ := pem.Decode([]byte(pubPEM))
			require.NotNil(t, pubBlock)
			assert.Equal(t, "PUBLIC KEY", pubBlock.Type)
			gotOID, _, err := parseHybridSPKI(pubBlock.Bytes)
			require.NoError(t, err)
			assert.True(t, gotOID.Equal(tc.oid), "SPKI OID mismatch: got %v want %v", gotOID, tc.oid)

			privPEM, err := kp.PrivateKeyInPemFormat()
			require.NoError(t, err)
			privBlock, _ := pem.Decode([]byte(privPEM))
			require.NotNil(t, privBlock)
			assert.Equal(t, "PRIVATE KEY", privBlock.Type)
			gotOID, _, err = parseHybridPKCS8(privBlock.Bytes)
			require.NoError(t, err)
			assert.True(t, gotOID.Equal(tc.oid), "PKCS#8 OID mismatch: got %v want %v", gotOID, tc.oid)
		})
	}
}

func TestIsHybridKeyTypeIncludesNewTypes(t *testing.T) {
	assert.True(t, IsHybridKeyType(HybridXWingKey))
	assert.True(t, IsHybridKeyType(HybridSecp256r1MLKEM768Key))
	assert.True(t, IsHybridKeyType(HybridSecp384r1MLKEM1024Key))
	assert.False(t, IsHybridKeyType(EC256Key))
	assert.False(t, IsHybridKeyType(RSA2048Key))
}
