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

	"github.com/opentdf/platform/protocol/go/policy"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cryptoproviders"
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
	provider := NewDefault(logger.CreateTestLogger())
	assert.Equal(t, "default", provider.Identifier())
}

func TestDefault_Symmetric_RoundTrip(t *testing.T) {
	provider := NewDefault(logger.CreateTestLogger())
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
	provider := NewDefault(logger.CreateTestLogger())
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
	provider := NewDefault(logger.CreateTestLogger())
	ctx := context.Background()

	privatePEM, publicPEM, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)

	plainText := []byte("this is a secret message for RSA")

	// Encrypt Options
	encryptOpts := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: publicPEM, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048},
	}
	encryptOpts.Hash = crypto.SHA1

	// Encrypt
	cipherText, ephemeralKey, err := provider.EncryptAsymmetric(ctx, encryptOpts)
	require.NoError(t, err)
	require.NotEmpty(t, cipherText)
	require.Nil(t, ephemeralKey) // No ephemeral key for RSA
	assert.NotEqual(t, plainText, cipherText)

	// Decrypt Options
	decryptOpts := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: privatePEM, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048},
		// KEK not needed for default provider direct decryption
	}

	// Decrypt
	decryptedText, err := provider.DecryptAsymmetric(ctx, decryptOpts)
	require.NoError(t, err)
	assert.Equal(t, plainText, decryptedText)
}

func TestDefault_Asymmetric_RSA_Errors(t *testing.T) {
	provider := NewDefault(logger.CreateTestLogger())
	ctx := context.Background()
	_, publicPEM, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	plainText := []byte("test rsa error")

	// Encrypt with bad public key PEM
	encryptOptsBadPub := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: []byte("bad pem"), Algorithm: policy.Algorithm_ALGORITHM_RSA_2048},
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsBadPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Encrypt with non-RSA public key (using EC key as wrong type)
	_, ecPublicPEM, err := generateECKeyPairPEM(elliptic.P256())
	require.NoError(t, err)
	encryptOptsWrongType := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: ecPublicPEM, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048}, // Use EC public key with RSA algorithm
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an RSA public key") // Error comes from type assertion after parsing

	// --- Decryption Errors ---
	encryptOptsGood := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: publicPEM, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048},
	}
	encryptOptsGood.Hash = crypto.SHA1 // Specify hash function for RSA-OAEP
	cipherText, _, err := provider.EncryptAsymmetric(ctx, encryptOptsGood)
	require.NoError(t, err)

	// Decrypt with bad private key PEM
	decryptOptsBadPriv := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: []byte("bad pem"), Algorithm: policy.Algorithm_ALGORITHM_RSA_2048},
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsBadPriv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Decrypt with non-RSA private key
	ecPrivatePEMForWrongType, _, err := generateECKeyPairPEM(elliptic.P256())
	require.NoError(t, err)
	decryptOptsWrongType := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: ecPrivatePEMForWrongType, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048}, // Use EC private key with RSA algorithm
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an RSA private key") // Updated to match actual error

	// Decrypt with wrong private key
	wrongRSAPrivatePEM, _, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	decryptOptsWrongKey := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: wrongRSAPrivatePEM, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048}, // Use a different RSA private key
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongKey)
	assert.Error(t, err) // Decryption error (likely crypto/rsa: decryption error)
	assert.Contains(t, err.Error(), "decryption error")
}

func TestDefault_Asymmetric_EC_RoundTrip(t *testing.T) {
	provider := NewDefault(logger.CreateTestLogger())
	ctx := context.Background()

	// Use P-256 curve
	curve := elliptic.P256()
	privatePEM, publicPEM, err := generateECKeyPairPEM(curve)
	require.NoError(t, err)

	plainText := []byte("this is a secret message for EC")

	// Encrypt Options
	encryptOpts := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: publicPEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
		// No Hash needed for EC
	}
	// In the context of rewrap, EphemeralKey is used for the recipient's public key
	encryptOpts.EphemeralKey = publicPEM

	// Encrypt
	cipherText, ephemeralPubKeyBytes, err := provider.EncryptAsymmetric(ctx, encryptOpts)
	require.NoError(t, err)
	require.NotEmpty(t, cipherText)
	require.NotEmpty(t, ephemeralPubKeyBytes)
	assert.NotEqual(t, plainText, cipherText)

	// PEM encode the ephemeral public key for decryption
	ephemeralPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ephemeralPubKeyBytes})

	// Decrypt Options
	decryptOpts := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: privatePEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
		// KEK not needed
	}

	decryptOpts.EphemeralKey = ephemeralPubPEM

	// Decrypt
	decryptedText, err := provider.DecryptAsymmetric(ctx, decryptOpts)
	require.NoError(t, err)
	assert.Equal(t, plainText, decryptedText)
}

func TestDefault_Asymmetric_EC_Errors(t *testing.T) {
	provider := NewDefault(logger.CreateTestLogger())
	ctx := context.Background()
	privatePEM, publicPEM, err := generateECKeyPairPEM(elliptic.P256())
	require.NoError(t, err)
	plainText := []byte("test ec error")

	// Encrypt with bad public key PEM
	encryptOptsBadPub := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: []byte("bad pem"), Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
	}
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsBadPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Encrypt with non-EC public key (using RSA key as wrong type)
	_, rsaPublicPEMForWrongType, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	encryptOptsWrongType := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: rsaPublicPEMForWrongType, Algorithm: policy.Algorithm_ALGORITHM_EC_P256}, // Use RSA public key with EC algorithm
	}
	encryptOptsWrongType.EphemeralKey = rsaPublicPEMForWrongType
	_, _, err = provider.EncryptAsymmetric(ctx, encryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDH public key") // Error comes from type assertion

	// --- Decryption Errors ---
	encryptOptsGood := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: publicPEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
	}
	// In the context of rewrap, EphemeralKey is used for the recipient's public key
	encryptOptsGood.EphemeralKey = publicPEM
	cipherText, ephemeralPubKeyBytes, err := provider.EncryptAsymmetric(ctx, encryptOptsGood)
	require.NoError(t, err)
	require.NotEmpty(t, ephemeralPubKeyBytes)

	// PEM encode the ephemeral public key for decryption
	ephemeralPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ephemeralPubKeyBytes})

	// Decrypt with bad private key PEM
	decryptOptsBadPriv := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: []byte("bad pem"), Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
	}
	decryptOptsBadPriv.EphemeralKey = ephemeralPubPEM
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsBadPriv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Decrypt with non-EC private key
	rsaPrivatePEMForWrongType2, _, err := generateRSAKeyPairPEM(2048)
	require.NoError(t, err)
	decryptOptsWrongType := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: rsaPrivatePEMForWrongType2, Algorithm: policy.Algorithm_ALGORITHM_EC_P256}, // Use RSA private key with EC algorithm
	}
	decryptOptsWrongType.EphemeralKey = ephemeralPubPEM
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDH private key") // Updated to match actual error

	// Decrypt with wrong private key
	wrongECPrivatePEM, _, err := generateECKeyPairPEM(elliptic.P256())
	require.NoError(t, err)
	decryptOptsWrongKey := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: wrongECPrivatePEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256}, // Use a different EC private key
	}
	decryptOptsWrongKey.EphemeralKey = ephemeralPubPEM
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongKey)
	assert.Error(t, err) // Should be GCM auth error as shared secret will differ
	assert.Contains(t, err.Error(), "cipher: message authentication failed")

	// Decrypt with bad ephemeral key PEM
	decryptOptsBadEphemeral := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: privatePEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
	}
	decryptOptsBadEphemeral.EphemeralKey = []byte("bad pem")
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsBadEphemeral)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Decrypt with non-EC ephemeral key
	decryptOptsWrongEphemeralType := cryptoproviders.DecryptOpts{
		CipherText: cipherText,
		KeyRef:     cryptoproviders.KeyRef{Key: privatePEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
	}
	decryptOptsWrongEphemeralType.EphemeralKey = rsaPublicPEMForWrongType
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsWrongEphemeralType)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDH public key (ephemeral)")

	// Decrypt with ciphertext too short
	decryptOptsShortCipher := cryptoproviders.DecryptOpts{
		CipherText: []byte("short"),
		KeyRef:     cryptoproviders.KeyRef{Key: privatePEM, Algorithm: policy.Algorithm_ALGORITHM_EC_P256},
	}
	decryptOptsShortCipher.EphemeralKey = ephemeralPubPEM
	_, err = provider.DecryptAsymmetric(ctx, decryptOptsShortCipher)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDefault_UnsupportedAlgorithm(t *testing.T) {
	provider := NewDefault(logger.CreateTestLogger())
	ctx := context.Background()
	plainText := []byte("test")
	// Encrypt Asymmetric
	encryptOpts := cryptoproviders.EncryptOpts{
		Data:   plainText,
		KeyRef: cryptoproviders.KeyRef{Key: []byte{}, Algorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED}, // Use unspecified algorithm
	}
	_, _, err := provider.EncryptAsymmetric(ctx, encryptOpts)
	assert.Error(t, err)
	assert.EqualError(t, err, "unsupported algorithm")

	// Decrypt Asymmetric
	decryptOpts := cryptoproviders.DecryptOpts{
		CipherText: []byte("dummy cipher"),
		KeyRef:     cryptoproviders.KeyRef{Key: []byte{}, Algorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED}, // Use unspecified algorithm
	}
	_, err = provider.DecryptAsymmetric(ctx, decryptOpts)
	assert.Error(t, err)
	assert.EqualError(t, err, "unsupported algorithm")
}
