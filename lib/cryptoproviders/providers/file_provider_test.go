package providers

import (
	"context"
	"crypto/aes"    // Added for KEK generation/use
	"crypto/cipher" // Added for AES-GCM
	"crypto/rand"   // Added for KEK generation and nonce
	"crypto/rsa"    // Added for RSA key generation/use
	"crypto/sha256" // Added for OAEP hash
	"crypto/x509"   // Added for key parsing/marshalling
	"encoding/pem"  // Added for saving keys in PEM format
	"io"            // Added for nonce generation
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/lib/cryptoproviders"
	"github.com/opentdf/platform/protocol/go/policy" // Added for algorithm types
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helper Functions ---

// generateRSAKeys generates a new RSA key pair and saves them to files in PEM format.
func generateRSAKeys(t *testing.T, dir string, privKeyFile, pubKeyFile string) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048) // Use 2048 for testing
	require.NoError(t, err)
	pubKey := &privKey.PublicKey

	// Save private key (PKCS1 PEM)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes})
	err = os.WriteFile(filepath.Join(dir, privKeyFile), privKeyPem, 0600)
	require.NoError(t, err)

	// Save public key (PKIX PEM)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	pubKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	err = os.WriteFile(filepath.Join(dir, pubKeyFile), pubKeyPem, 0600)
	require.NoError(t, err)

	return privKey, pubKey
}

// wrapKey encrypts data (e.g., a private key PEM) using AES-GCM with the given KEK.
func wrapKey(t *testing.T, kek, dataToWrap []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kek)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	wrapped := gcm.Seal(nonce, nonce, dataToWrap, nil)
	return wrapped
}

func TestFile_NewFileProvider(t *testing.T) {
	// Success case
	t.Run("Success", func(t *testing.T) {
		tempDir := t.TempDir()
		config := FileProviderConfig{BasePath: tempDir}
		provider, err := NewFileProvider(config)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, tempDir, provider.config.BasePath)
	})

	// Error: BasePath empty
	t.Run("Error_BasePathEmpty", func(t *testing.T) {
		config := FileProviderConfig{BasePath: ""}
		_, err := NewFileProvider(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "basePath cannot be empty")
	})

	// Error: BasePath does not exist
	t.Run("Error_BasePathNotExist", func(t *testing.T) {
		nonExistentPath := filepath.Join(t.TempDir(), "nonexistent")
		config := FileProviderConfig{BasePath: nonExistentPath}
		_, err := NewFileProvider(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	// Error: BasePath is a file, not a directory
	t.Run("Error_BasePathIsFile", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "testfile.txt")
		err := os.WriteFile(filePath, []byte("hello"), 0600)
		require.NoError(t, err)

		config := FileProviderConfig{BasePath: filePath}
		_, err = NewFileProvider(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a directory")
	})
}

func TestFile_Identifier(t *testing.T) {
	provider := FileProvider{} // Doesn't need config for Identifier()
	assert.Equal(t, FileProviderIdentifier, provider.Identifier())
}

func TestFile_resolvePath(t *testing.T) {
	tempDir := t.TempDir()
	config := FileProviderConfig{BasePath: tempDir}
	provider, err := NewFileProvider(config)
	require.NoError(t, err)

	t.Run("Success_ValidRelativePath", func(t *testing.T) {
		relPath := "keys/mykey.pem"
		expectedPath := filepath.Join(tempDir, "keys", "mykey.pem")
		resolvedPath, err := provider.resolvePath([]byte(relPath))
		require.NoError(t, err)
		assert.Equal(t, expectedPath, resolvedPath)
	})

	t.Run("Success_ValidRelativePath_NoSubdir", func(t *testing.T) {
		relPath := "mykey.pem"
		expectedPath := filepath.Join(tempDir, "mykey.pem")
		resolvedPath, err := provider.resolvePath([]byte(relPath))
		require.NoError(t, err)
		assert.Equal(t, expectedPath, resolvedPath)
	})

	t.Run("Error_AbsolutePath", func(t *testing.T) {
		absPath := "/etc/passwd"
		_, err := provider.resolvePath([]byte(absPath))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid relative key path")
	})

	t.Run("Error_PathTraversal_Up", func(t *testing.T) {
		relPath := "../secrets.txt"
		_, err := provider.resolvePath([]byte(relPath))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid relative key path")
	})

	t.Run("Error_PathTraversal_UpDir", func(t *testing.T) {
		relPath := "../../etc/passwd"
		_, err := provider.resolvePath([]byte(relPath))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid relative key path")
	})

	t.Run("Success_ValidRelativePath_WithBase", func(t *testing.T) {
		// Even if it resolves within BasePath after Join, Clean should handle it safely
		relPath := "keys/../mykey.pem" // Resolves to mykey.pem, but uses '..'
		expectedPath := filepath.Join(tempDir, "mykey.pem")
		resolvedPath, err := provider.resolvePath([]byte(relPath))
		require.NoError(t, err) // filepath.Clean handles this case safely
		assert.Equal(t, expectedPath, resolvedPath)
	})

	t.Run("Success_EmptyPath", func(t *testing.T) {
		// Empty path resolves to base path which is valid usage
		relPath := ""
		expectedPath := tempDir
		resolvedPath, err := provider.resolvePath([]byte(relPath))
		require.NoError(t, err)
		assert.Equal(t, expectedPath, resolvedPath)
	})
}

// Placeholder for future tests
func TestFile_EncryptSymmetric(t *testing.T) {
	provider := FileProvider{} // Config doesn't matter for this check
	_, err := provider.EncryptSymmetric(context.Background(), []byte("key"), []byte("data"))
	require.Error(t, err)
	assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
	assert.Contains(t, err.Error(), "not implemented by file provider")
}

func TestFile_DecryptSymmetric(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	config := FileProviderConfig{BasePath: tempDir}
	provider, err := NewFileProvider(config)
	require.NoError(t, err)

	// --- Test Data ---
	kek := make([]byte, 32) // AES-256 key
	_, err = rand.Read(kek)
	require.NoError(t, err)

	kekFileName := "test.kek"
	kekFilePath := filepath.Join(tempDir, kekFileName)
	err = os.WriteFile(kekFilePath, kek, 0600)
	require.NoError(t, err)

	originalData := []byte("this is the secret unwrapped key") // Data to be "wrapped"

	// Encrypt data using AES-GCM to simulate wrapped key
	block, err := aes.NewCipher(kek)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	wrappedData := gcm.Seal(nonce, nonce, originalData, nil) // Prepend nonce to ciphertext

	// --- Success Case ---
	t.Run("Success", func(t *testing.T) {
		unwrapped, err := provider.DecryptSymmetric(ctx, []byte(kekFileName), wrappedData)
		require.NoError(t, err)
		assert.Equal(t, originalData, unwrapped)
	})

	// --- Error Cases ---
	t.Run("Error_KEKFileNotFound", func(t *testing.T) {
		_, err := provider.DecryptSymmetric(ctx, []byte("nonexistent.kek"), wrappedData)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "read KEK")
		assert.Contains(t, err.Error(), "no such file or directory") // OS specific error part
	})

	t.Run("Error_InvalidKEKPath", func(t *testing.T) {
		_, err := provider.DecryptSymmetric(ctx, []byte("../outside_kek.bin"), wrappedData)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "resolve KEK path")
		assert.Contains(t, err.Error(), "invalid relative key path")
	})

	t.Run("Error_CiphertextTooShort", func(t *testing.T) {
		shortCiphertext := []byte("short")
		_, err := provider.DecryptSymmetric(ctx, []byte(kekFileName), shortCiphertext)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("Error_DecryptionFailed_BadNonce", func(t *testing.T) {
		badWrappedData := make([]byte, len(wrappedData))
		copy(badWrappedData, wrappedData)
		badWrappedData[0] ^= 0xff // Flip a bit in the nonce part

		_, err := provider.DecryptSymmetric(ctx, []byte(kekFileName), badWrappedData)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to decrypt/unwrap key") // GCM open fails
		// Underlying error might be "cipher: message authentication failed"
	})

	t.Run("Error_DecryptionFailed_WrongKEK", func(t *testing.T) {
		wrongKek := make([]byte, 32)
		_, err = rand.Read(wrongKek)
		require.NoError(t, err)
		wrongKekFileName := "wrong.kek"
		wrongKekFilePath := filepath.Join(tempDir, wrongKekFileName)
		err = os.WriteFile(wrongKekFilePath, wrongKek, 0600)
		require.NoError(t, err)

		_, err = provider.DecryptSymmetric(ctx, []byte(wrongKekFileName), wrappedData)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to decrypt/unwrap key") // GCM open fails
	})

	t.Run("Error_KEKNotAESKey", func(t *testing.T) {
		badKek := []byte("this is not long enough for an AES key")
		badKekFileName := "bad.kek"
		badKekFilePath := filepath.Join(tempDir, badKekFileName)
		err = os.WriteFile(badKekFilePath, badKek, 0600)
		require.NoError(t, err)

		_, err = provider.DecryptSymmetric(ctx, []byte(badKekFileName), wrappedData)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to create AES cipher") // Error from aes.NewCipher
		assert.Contains(t, err.Error(), "invalid key size")
	})
}
func TestFile_EncryptAsymmetric(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	config := FileProviderConfig{BasePath: tempDir}
	provider, err := NewFileProvider(config)
	require.NoError(t, err)

	// --- Test Data ---
	privKeyFile := "test_priv.pem"
	pubKeyFile := "test_pub.pem"
	_, _ = generateRSAKeys(t, tempDir, privKeyFile, pubKeyFile) // Ignore returned keys, just need files created

	plainText := []byte("secret data for asymmetric encryption")

	// --- Success Case (RSA) ---
	t.Run("Success_RSA", func(t *testing.T) {
		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte(pubKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			Data:   plainText,
			// Hash is defaulted to SHA256 by the provider currently
		}
		cipherText, ephemeralKey, err := provider.EncryptAsymmetric(ctx, opts)
		require.NoError(t, err)
		assert.NotNil(t, cipherText)
		assert.Nil(t, ephemeralKey) // No ephemeral key for RSA

		// Verify by decrypting manually (using the private key we generated but didn't give to provider)
		privKeyBytesPEM, err := os.ReadFile(filepath.Join(tempDir, privKeyFile))
		require.NoError(t, err)
		block, _ := pem.Decode(privKeyBytesPEM)
		require.NotNil(t, block)
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		require.NoError(t, err)

		decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherText, nil)
		require.NoError(t, err)
		assert.Equal(t, plainText, decrypted)
	})

	// --- Error Cases ---
	t.Run("Error_PubKeyFileNotFound", func(t *testing.T) {
		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte("nonexistent_pub.pem"), policy.Algorithm_ALGORITHM_RSA_2048),
			Data:   plainText,
		}
		_, _, err := provider.EncryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "read public key")
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("Error_InvalidPubKeyPath", func(t *testing.T) {
		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte("../outside_pub.pem"), policy.Algorithm_ALGORITHM_RSA_2048),
			Data:   plainText,
		}
		_, _, err := provider.EncryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "resolve pubkey path")
		assert.Contains(t, err.Error(), "invalid relative key path")
	})

	t.Run("Error_PubKeyNotPEM", func(t *testing.T) {
		badPubKeyFile := "bad_pub.key"
		err := os.WriteFile(filepath.Join(tempDir, badPubKeyFile), []byte("this is not pem"), 0600)
		require.NoError(t, err)

		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte(badPubKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			Data:   plainText,
		}
		_, _, err = provider.EncryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("Error_PubKeyNotRSA", func(t *testing.T) {
		// We'll simulate this by trying to encrypt with the private key file path
		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte(privKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			Data:   plainText,
		}
		_, _, err := provider.EncryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		// The error might be in parsing (PKIX vs PKCS1) or type assertion
		assert.Contains(t, err.Error(), "EncryptAsymmetric") // General check
	})

	t.Run("Error_UnsupportedAlgorithm_EC", func(t *testing.T) {
		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte(pubKeyFile), policy.Algorithm_ALGORITHM_EC_P256), // Use EC algo
			Data:   plainText,
		}
		_, _, err := provider.EncryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "EC encryption not implemented")
	})

	t.Run("Error_UnsupportedAlgorithm_Other", func(t *testing.T) {
		opts := cryptoproviders.EncryptOpts{
			KeyRef: cryptoproviders.NewKeyRef([]byte(pubKeyFile), policy.Algorithm_ALGORITHM_UNSPECIFIED), // Use unspecified algo
			Data:   plainText,
		}
		_, _, err := provider.EncryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})
}

func TestFile_DecryptAsymmetric(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	config := FileProviderConfig{BasePath: tempDir}
	provider, err := NewFileProvider(config)
	require.NoError(t, err)

	// --- Test Data ---
	privKeyFile := "test_priv.pem"
	pubKeyFile := "test_pub.pem"
	_, pubKey := generateRSAKeys(t, tempDir, privKeyFile, pubKeyFile) // Ignore privKey, need pubKey for manual encryption

	plainText := []byte("secret data for asymmetric decryption")

	// Encrypt manually using the public key
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plainText, nil)
	require.NoError(t, err)

	// --- Success Case (RSA, No KEK) ---
	t.Run("Success_RSA_NoKEK", func(t *testing.T) {
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(privKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
			KEK:        nil, // Explicitly nil
		}
		decrypted, err := provider.DecryptAsymmetric(ctx, opts)
		require.NoError(t, err)
		assert.Equal(t, plainText, decrypted)
	})

	// --- Success Case (RSA, WithKEK) ---
	t.Run("Success_RSA_WithKEK", func(t *testing.T) {
		// Create a KEK
		kek := make([]byte, 32)
		_, err = rand.Read(kek)
		require.NoError(t, err)

		// Read the original private key PEM
		privKeyPemBytes, err := os.ReadFile(filepath.Join(tempDir, privKeyFile))
		require.NoError(t, err)

		// Wrap the private key PEM with the KEK
		wrappedPrivKeyBytes := wrapKey(t, kek, privKeyPemBytes)
		wrappedPrivKeyFileName := "wrapped_priv.pem.enc"
		err = os.WriteFile(filepath.Join(tempDir, wrappedPrivKeyFileName), wrappedPrivKeyBytes, 0600)
		require.NoError(t, err)

		// Decrypt using the wrapped key file and the KEK
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(wrappedPrivKeyFileName), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
			KEK:        kek, // Provide the KEK
		}
		decrypted, err := provider.DecryptAsymmetric(ctx, opts)
		require.NoError(t, err)
		assert.Equal(t, plainText, decrypted)
	})

	// --- Error Cases ---
	t.Run("Error_PrivKeyFileNotFound", func(t *testing.T) {
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte("nonexistent_priv.pem"), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
		}
		_, err := provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "read private key")
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("Error_InvalidPrivKeyPath", func(t *testing.T) {
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte("../outside_priv.pem"), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
		}
		_, err := provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "resolve privkey path")
		assert.Contains(t, err.Error(), "invalid relative key path")
	})

	t.Run("Error_PrivKeyNotPEM", func(t *testing.T) {
		badPrivKeyFile := "bad_priv.key"
		err := os.WriteFile(filepath.Join(tempDir, badPrivKeyFile), []byte("this is not pem"), 0600)
		require.NoError(t, err)

		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(badPrivKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
		}
		_, err = provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("Error_PrivKeyNotRSA", func(t *testing.T) {
		// We'll simulate this by trying to decrypt with the public key file path
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(pubKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
		}
		_, err := provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		// Error could be in parsing (PKCS1/PKCS8) or type assertion
		assert.Contains(t, err.Error(), "DecryptAsymmetric") // General check
	})

	t.Run("Error_DecryptionFailed_BadCiphertext", func(t *testing.T) {
		badCipherText := []byte("this is not the right ciphertext")
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(privKeyFile), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: badCipherText,
		}
		_, err := provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "RSA decryption failed")
		// Underlying error likely "crypto/rsa: decryption error"
	})

	t.Run("Error_KEKUnwrap_WrongKEK", func(t *testing.T) {
		kek := make([]byte, 32)
		_, err = rand.Read(kek)
		require.NoError(t, err)
		privKeyPemBytes, err := os.ReadFile(filepath.Join(tempDir, privKeyFile))
		require.NoError(t, err)
		wrappedPrivKeyBytes := wrapKey(t, kek, privKeyPemBytes)
		wrappedPrivKeyFileName := "wrapped_priv_wrong_kek.pem.enc"
		err = os.WriteFile(filepath.Join(tempDir, wrappedPrivKeyFileName), wrappedPrivKeyBytes, 0600)
		require.NoError(t, err)

		wrongKek := make([]byte, 32) // A different KEK
		_, err = rand.Read(wrongKek)
		require.NoError(t, err)

		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(wrappedPrivKeyFileName), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
			KEK:        wrongKek, // Use the wrong KEK
		}
		_, err = provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to unwrap private key")
		assert.Contains(t, err.Error(), "GCM open")
	})

	t.Run("Error_KEKUnwrap_CorruptedWrappedKey", func(t *testing.T) {
		kek := make([]byte, 32)
		_, err = rand.Read(kek)
		require.NoError(t, err)
		privKeyPemBytes, err := os.ReadFile(filepath.Join(tempDir, privKeyFile))
		require.NoError(t, err)
		wrappedPrivKeyBytes := wrapKey(t, kek, privKeyPemBytes)
		wrappedPrivKeyBytes[0] ^= 0xff // Corrupt the nonce part
		wrappedPrivKeyFileName := "wrapped_priv_corrupt.pem.enc"
		err = os.WriteFile(filepath.Join(tempDir, wrappedPrivKeyFileName), wrappedPrivKeyBytes, 0600)
		require.NoError(t, err)

		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(wrappedPrivKeyFileName), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
			KEK:        kek,
		}
		_, err = provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to unwrap private key")
		assert.Contains(t, err.Error(), "GCM open")
	})

	t.Run("Error_KEKUnwrap_KEKNotAESKey", func(t *testing.T) {
		kek := []byte("not an aes key")
		_, err := os.ReadFile(filepath.Join(tempDir, privKeyFile)) // Ignore bytes, just check read error
		require.NoError(t, err)
		// Wrapping would fail here, so we just test the decrypt path directly
		wrappedPrivKeyFileName := "wrapped_priv_bad_kek.pem.enc"
		err = os.WriteFile(filepath.Join(tempDir, wrappedPrivKeyFileName), []byte("dummy wrapped data"), 0600) // Content doesn't matter much here
		require.NoError(t, err)

		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(wrappedPrivKeyFileName), policy.Algorithm_ALGORITHM_RSA_2048),
			CipherText: cipherText,
			KEK:        kek, // Use bad KEK
		}
		_, err = provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "failed to create AES cipher for KEK")
		assert.Contains(t, err.Error(), "invalid key size")
	})

	t.Run("Error_UnsupportedAlgorithm_EC", func(t *testing.T) {
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(privKeyFile), policy.Algorithm_ALGORITHM_EC_P256), // Use EC algo
			CipherText: cipherText,
		}
		_, err := provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "EC decryption not implemented")
	})

	t.Run("Error_UnsupportedAlgorithm_Other", func(t *testing.T) {
		opts := cryptoproviders.DecryptOpts{
			KeyRef:     cryptoproviders.NewKeyRef([]byte(privKeyFile), policy.Algorithm_ALGORITHM_UNSPECIFIED), // Use unspecified algo
			CipherText: cipherText,
		}
		_, err := provider.DecryptAsymmetric(ctx, opts)
		require.Error(t, err)
		assert.ErrorAs(t, err, &cryptoproviders.ErrOperationFailed{})
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})
}

// TODO: Add tests for DecryptAsymmetric (RSA, with/without KEK)
