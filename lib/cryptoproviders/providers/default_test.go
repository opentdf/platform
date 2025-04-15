package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/opentdf/platform/lib/cryptoproviders"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate RSA key pair in PEM format
func generateRSAKeyPairPEM(bits int) (privatePEM, publicPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes})

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes})

	return privatePEM, publicPEM, nil
}

// Helper function to generate EC key pair in PEM format
func generateECKeyPairPEM(curve elliptic.Curve) (privatePEM, publicPEM []byte, err error) {
	// Generate ECDSA key first, as it's more common for PEM encoding
	ecdsaPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Encode private key
	privateBytes, err := x509.MarshalECPrivateKey(ecdsaPriv)
	if err != nil {
		return nil, nil, err
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateBytes})

	// Encode public key
	publicBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes})

	return privatePEM, publicPEM, nil
}

func TestDefault_Identifier(t *testing.T) {
	provider := NewDefault()
	assert.Equal(t, "default", provider.Identifier())
}

func TestDefault_Symmetric_RoundTrip(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()
	key := make([]byte, 32) // AES-256 key
	_, err := rand.Read(key)
	require.NoError(t, err)

	plainText := []byte("this is a secret message for symmetric encryption")

	// Encrypt
	cipherText, err := provider.EncryptSymmetric(ctx, key, plainText)
	require.NoError(t, err)
	require.NotEmpty(t, cipherText)
	assert.NotEqual(t, plainText, cipherText)

	// Decrypt
	decryptedText, err := provider.DecryptSymmetric(ctx, key, cipherText)
	require.NoError(t, err)
	assert.Equal(t, plainText, decryptedText)
}

func TestDefault_Symmetric_Errors(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	plainText := []byte("test")

	// Encrypt with invalid key size (should error in NewCipher)
	invalidKey := []byte("short")
	_, err = provider.EncryptSymmetric(ctx, invalidKey, plainText)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "crypto/aes: invalid key size")

	// Decrypt with invalid key size
	cipherText, err := provider.EncryptSymmetric(ctx, key, plainText)
	require.NoError(t, err)
	_, err = provider.DecryptSymmetric(ctx, invalidKey, cipherText)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "crypto/aes: invalid key size")

	// Decrypt with wrong key
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)
	_, err = provider.DecryptSymmetric(ctx, wrongKey, cipherText)
	assert.Error(t, err) // Should be a GCM authentication error
	assert.Contains(t, err.Error(), "cipher: message authentication failed")

	// Decrypt with ciphertext too short
	shortCipherText := []byte("short")
	_, err = provider.DecryptSymmetric(ctx, key, shortCipherText)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDefault_Asymmetric_RSA_RoundTrip(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()

	privatePEM, publicPEM, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)

	plainText := []byte("this is a secret message for RSA")
	hash := crypto.SHA256 // Default hash used in DecryptAsymmetric

	// Encrypt Options
	encryptOpts := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(publicPEM, policy.Algorithm_ALGORITHM_RSA_2048),
		Data:   plainText,
		Hash:   hash,
	}

	// Encrypt
	cipherText, ephemeralKey, err := provider.EncryptAsymmetric(ctx, encryptOpts)
	require.NoError(t, err)
	require.NotEmpty(t, cipherText)
	require.Nil(t, ephemeralKey) // No ephemeral key for RSA
	assert.NotEqual(t, plainText, cipherText)

	// Decrypt Options
	decryptOpts := cryptoproviders.DecryptOpts{
		KeyRef:     cryptoproviders.NewKeyRef(privatePEM, policy.Algorithm_ALGORITHM_RSA_2048),
		CipherText: cipherText,
		// KEK not needed for default provider direct decryption
	}

	// Decrypt
	decryptedText, err := provider.DecryptAsymmetric(ctx, decryptOpts)
	require.NoError(t, err)
	assert.Equal(t, plainText, decryptedText)
}

func TestDefault_Asymmetric_RSA_Errors(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()
	_, publicPEM, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	plainText := []byte("test rsa error")
	hash := crypto.SHA256

	// Encrypt with bad public key PEM
	encryptOptsBadPub := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef([]byte("bad pem"), policy.Algorithm_ALGORITHM_RSA_2048),
		Data:   plainText,
		Hash:   hash,
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsBadPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Encrypt with non-RSA public key (using EC key as wrong type)
	_, ecPubPEM, err := generateECKeyPairPEM(elliptic.P256())
	require.NoError(t, err)
	encryptOptsWrongType := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(ecPubPEM, policy.Algorithm_ALGORITHM_RSA_2048), // Mismatched algo
		Data:   plainText,
		Hash:   hash,
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an RSA public key") // Error comes from type assertion after parsing

	// --- Decryption Errors ---
	encryptOptsGood := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(publicPEM, policy.Algorithm_ALGORITHM_RSA_2048),
		Data:   plainText,
		Hash:   hash,
	}
	cipherText, _, err := provider.EncryptAsymmetric(ctx, encryptOptsGood)
	require.NoError(t, err)

	// Decrypt with bad private key PEM
	decryptOptsBadPriv := cryptoproviders.DecryptOpts{
		KeyRef:     cryptoproviders.NewKeyRef([]byte("bad pem"), policy.Algorithm_ALGORITHM_RSA_2048),
		CipherText: cipherText,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsBadPriv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Decrypt with non-RSA private key
	ecPrivPEM, _, err := generateECKeyPairPEM(elliptic.P256())
	require.NoError(t, err)
	decryptOptsWrongType := cryptoproviders.DecryptOpts{
		KeyRef:     cryptoproviders.NewKeyRef(ecPrivPEM, policy.Algorithm_ALGORITHM_RSA_2048), // Mismatched algo
		CipherText: cipherText,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an RSA private key") // Updated to match actual error

	// Decrypt with wrong private key
	wrongPrivPEM, _, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	decryptOptsWrongKey := cryptoproviders.DecryptOpts{
		KeyRef:     cryptoproviders.NewKeyRef(wrongPrivPEM, policy.Algorithm_ALGORITHM_RSA_2048),
		CipherText: cipherText,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongKey)
	assert.Error(t, err) // Decryption error (likely crypto/rsa: decryption error)
	assert.Contains(t, err.Error(), "decryption error")
}

func TestDefault_Asymmetric_EC_RoundTrip(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()

	// Use P-256 curve
	curve := elliptic.P256()
	algo := policy.Algorithm_ALGORITHM_EC_P256
	privatePEM, publicPEM, err := generateECKeyPairPEM(curve)
	require.NoError(t, err)

	plainText := []byte("this is a secret message for EC")

	// Encrypt Options
	encryptOpts := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(publicPEM, algo),
		Data:   plainText,
		// No Hash needed for EC
	}

	// Encrypt
	cipherText, ephemeralPubPEM, err := provider.EncryptAsymmetric(ctx, encryptOpts)
	require.NoError(t, err)
	require.NotEmpty(t, cipherText)
	require.NotEmpty(t, ephemeralPubPEM)
	assert.NotEqual(t, plainText, cipherText)

	// Decrypt Options
	decryptOpts := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef(privatePEM, algo),
		CipherText:   cipherText,
		EphemeralKey: ephemeralPubPEM,
		// KEK not needed
	}

	// Decrypt
	decryptedText, err := provider.DecryptAsymmetric(ctx, decryptOpts)
	require.NoError(t, err)
	assert.Equal(t, plainText, decryptedText)
}

func TestDefault_Asymmetric_EC_Errors(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()
	curve := elliptic.P256()
	algo := policy.Algorithm_ALGORITHM_EC_P256
	privatePEM, publicPEM, err := generateECKeyPairPEM(curve)
	require.NoError(t, err)
	plainText := []byte("test ec error")

	// Encrypt with bad public key PEM
	encryptOptsBadPub := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef([]byte("bad pem"), algo),
		Data:   plainText,
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsBadPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Encrypt with non-EC public key (using RSA key as wrong type)
	_, rsaPubPEM, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	encryptOptsWrongType := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(rsaPubPEM, algo), // Mismatched algo
		Data:   plainText,
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDH public key") // Error comes from type assertion

	// --- Decryption Errors ---
	encryptOptsGood := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(publicPEM, algo),
		Data:   plainText,
	}
	cipherText, ephemeralPubPEM, err := provider.EncryptAsymmetric(ctx, encryptOptsGood)
	require.NoError(t, err)
	require.NotEmpty(t, ephemeralPubPEM)

	// Decrypt with bad private key PEM
	decryptOptsBadPriv := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef([]byte("bad pem"), algo),
		CipherText:   cipherText,
		EphemeralKey: ephemeralPubPEM,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsBadPriv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Decrypt with non-EC private key
	rsaPrivPEM, _, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	decryptOptsWrongType := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef(rsaPrivPEM, algo), // Mismatched algo
		CipherText:   cipherText,
		EphemeralKey: ephemeralPubPEM,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDH private key") // Updated to match actual error

	// Decrypt with wrong private key
	wrongPrivPEM, _, err := generateECKeyPairPEM(curve)
	require.NoError(t, err)
	decryptOptsWrongKey := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef(wrongPrivPEM, algo),
		CipherText:   cipherText,
		EphemeralKey: ephemeralPubPEM,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongKey)
	assert.Error(t, err) // Should be GCM auth error as shared secret will differ
	assert.Contains(t, err.Error(), "cipher: message authentication failed")

	// Decrypt with bad ephemeral key PEM
	decryptOptsBadEphemeral := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef(privatePEM, algo),
		CipherText:   cipherText,
		EphemeralKey: []byte("bad pem"),
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsBadEphemeral)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Decrypt with non-EC ephemeral key
	decryptOptsWrongEphemeralType := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef(privatePEM, algo),
		CipherText:   cipherText,
		EphemeralKey: rsaPubPEM, // Using RSA pub key here
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongEphemeralType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDH public key (ephemeral)")

	// Decrypt with ciphertext too short
	decryptOptsShortCipher := cryptoproviders.DecryptOpts{
		KeyRef:       cryptoproviders.NewKeyRef(privatePEM, algo),
		CipherText:   []byte("short"),
		EphemeralKey: ephemeralPubPEM,
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsShortCipher)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDefault_UnsupportedAlgorithm(t *testing.T) {
	provider := NewDefault()
	ctx := context.Background()
	plainText := []byte("test")
	keyBytes := []byte("dummy key")
	algo := policy.Algorithm_ALGORITHM_UNSPECIFIED

	// Encrypt Asymmetric
	encryptOpts := cryptoproviders.EncryptOpts{
		KeyRef: cryptoproviders.NewKeyRef(keyBytes, algo),
		Data:   plainText,
	}
	_, _, err := provider.EncryptAsymmetric(ctx, encryptOpts)
	assert.Error(t, err)
	assert.EqualError(t, err, "unsupported algorithm")

	// Decrypt Asymmetric
	decryptOpts := cryptoproviders.DecryptOpts{
		KeyRef:     cryptoproviders.NewKeyRef(keyBytes, algo),
		CipherText: []byte("dummy cipher"),
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOpts)
	assert.Error(t, err)
	assert.EqualError(t, err, "unsupported algorithm")
}
