package security

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockKeyDetails for testing
type MockKeyDetails struct {
	mock.Mock
	MID         string
	MAlgorithm  string
	MPrivateKey *policy.PrivateKeyCtx // Wrapped key
}

func (m *MockKeyDetails) ID() trust.KeyIdentifier {
	args := m.Called()

	if m.MID != "" { // Ensure no error is configured if MID is used
		return trust.KeyIdentifier(m.MID)
	}

	keyIden, ok := args.Get(0).(trust.KeyIdentifier)
	if ok {
		return keyIden
	}
	return ""
}

func (m *MockKeyDetails) Algorithm() ocrypto.KeyType {
	args := m.Called()
	return ocrypto.KeyType(args.String(0))
}

func (m *MockKeyDetails) IsLegacy() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockKeyDetails) ExportPrivateKey(_ context.Context) (*trust.PrivateKey, error) {
	args := m.Called()
	if pk, ok := args.Get(0).(*trust.PrivateKey); ok {
		return pk, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockKeyDetails) ExportPublicKey(_ context.Context, format trust.KeyType) (string, error) {
	args := m.Called(format)
	return args.String(0), args.Error(1)
}

func (m *MockKeyDetails) ExportCertificate(_ context.Context) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockKeyDetails) System() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockKeyDetails) ProviderConfig() *policy.KeyProviderConfig {
	args := m.Called()
	if pk, ok := args.Get(0).(*policy.KeyProviderConfig); ok {
		return pk
	}
	return nil
}

type MockEncapsulator struct {
	mock.Mock
}

func (m *MockEncapsulator) Encrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	if d, ok := args.Get(0).([]byte); ok {
		return d, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockEncapsulator) PublicKeyInPemFormat() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockEncapsulator) EphemeralKey() []byte {
	args := m.Called()
	if d, ok := args.Get(0).([]byte); ok {
		return d
	}
	return nil
}

// noOpEncapsulator is a test encapsulator that returns raw key data without encryption
type noOpEncapsulator struct{}

func (n *noOpEncapsulator) Encapsulate(pk ocrypto.ProtectedKey) ([]byte, error) {
	// Delegate to ProtectedKey to avoid accessing raw key directly
	return pk.Export(n)
}

func (n *noOpEncapsulator) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (n *noOpEncapsulator) PublicKeyAsPEM() (string, error) {
	return "", nil
}

func (n *noOpEncapsulator) EphemeralKey() []byte {
	return nil
}

// Helper function to wrap a key with AES-GCM
func wrapKeyWithAESGCM(keyToWrap []byte, rootKey []byte) (string, error) {
	gcm, err := ocrypto.NewAESGcm(rootKey)
	if err != nil {
		return "", fmt.Errorf("NewAESGcm: %w", err)
	}
	wrapped, err := gcm.Encrypt(keyToWrap)
	if err != nil {
		return "", fmt.Errorf("gcm.Encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(wrapped), nil
}

// Helper function to generate RSA key pair and PEM encode private key
func generateRSAKeyAndPEM() (ocrypto.RsaKeyPair, error) {
	return ocrypto.NewRSAKeyPair(2048)
}

// Helper function to generate EC key pair and PEM encode private key
func generateECKeyAndPEM(curve ocrypto.ECCMode) (ocrypto.ECKeyPair, error) {
	return ocrypto.NewECKeyPair(curve)
}

// Helper to create a test cache
func newTestCache(t *testing.T, log *logger.Logger) *cache.Cache {
	t.Helper()
	cm, err := cache.NewCacheManager(ristrettoMaxCost)
	require.NoError(t, err)
	c, err := cm.NewCache("testBasicManagerCache", log, cache.Options{
		Expiration: time.Duration(ristrettoCacheTTL) * time.Second,
	})
	require.NoError(t, err)
	return c
}

func TestNewBasicManager(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	validRootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // 32 bytes

	t.Run("successful creation", func(t *testing.T) {
		bm, err := NewBasicManager(log, testCache, validRootKeyHex)
		require.NoError(t, err)
		require.NotNil(t, bm)
		assert.Equal(t, BasicManagerName, bm.Name())
	})

	t.Run("invalid root key hex", func(t *testing.T) {
		_, err := NewBasicManager(log, testCache, "invalid-hex")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to hex decode root key")
	})
}

func TestBasicManager_Name(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	validRootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	bm, _ := NewBasicManager(log, testCache, validRootKeyHex)
	assert.Equal(t, BasicManagerName, bm.Name())
}

func TestBasicManager_Close(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	validRootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	bm, _ := NewBasicManager(log, testCache, validRootKeyHex)
	require.NotNil(t, bm.rootKey)
	bm.Close()
	assert.Nil(t, bm.rootKey, "rootKey should be nilled out after Close")
}

func TestBasicManager_unwrap(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	rootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	rootKey, _ := hex.DecodeString(rootKeyHex)
	samplePrivateKey := []byte("this is a secret key")
	kid := "test-kid-unwrap"

	wrappedKeyStr, err := wrapKeyWithAESGCM(samplePrivateKey, rootKey)
	require.NoError(t, err)

	bm, err := NewBasicManager(log, testCache, rootKeyHex)
	require.NoError(t, err)

	t.Run("cache miss, successful unwrap and cache", func(t *testing.T) {
		// Ensure cache is empty for this kid
		err := bm.cache.Delete(t.Context(), kid)
		require.NoError(t, err, "failed to delete from cache during setup")

		unwrapped, err := bm.unwrap(t.Context(), kid, wrappedKeyStr)
		require.NoError(t, err)
		assert.Equal(t, samplePrivateKey, unwrapped)

		// Verify it's in cache now
		time.Sleep(10 * time.Millisecond) // Give ristretto time to process the write
		cachedKey, err := bm.cache.Get(t.Context(), kid)
		require.NoError(t, err)
		assert.Equal(t, samplePrivateKey, cachedKey)
	})

	t.Run("cache hit", func(t *testing.T) {
		// Ensure key is in cache (from previous test or set it)
		err := bm.cache.Set(t.Context(), kid, samplePrivateKey, nil)
		require.NoError(t, err)

		unwrapped, err := bm.unwrap(t.Context(), kid, "this-should-not-be-used") // Provide dummy wrapped key
		require.NoError(t, err)
		assert.Equal(t, samplePrivateKey, unwrapped)
	})

	t.Run("invalid base64 wrapped key", func(t *testing.T) {
		err := bm.cache.Delete(t.Context(), "kid-invalid-b64")
		require.NoError(t, err, "failed to delete from cache during setup")
		_, err = bm.unwrap(t.Context(), "kid-invalid-b64", "---invalid-base64---")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to base64 decode wrapped key")
	})

	t.Run("decryption failure", func(t *testing.T) {
		err := bm.cache.Delete(t.Context(), "kid-decrypt-fail")
		require.NoError(t, err, "failed to delete from cache during setup")
		// Create a key wrapped with a *different* root key
		differentRootKeyHex := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" // 32 bytes
		differentRootKey, _ := hex.DecodeString(differentRootKeyHex)
		wronglyWrappedKeyStr, _ := wrapKeyWithAESGCM(samplePrivateKey, differentRootKey)

		_, err = bm.unwrap(t.Context(), "kid-decrypt-fail", wronglyWrappedKeyStr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt wrapped key") // This implies cipher.ErrAuthentication, which is correct
	})
}

func TestBasicManager_Decrypt(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	rootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	rootKey, _ := hex.DecodeString(rootKeyHex)

	rsaKey, err := generateRSAKeyAndPEM()
	require.NoError(t, err)
	rsaPrivKey, err := rsaKey.PrivateKeyInPemFormat()
	require.NoError(t, err)
	rsaPubKey, err := rsaKey.PublicKeyInPemFormat()
	require.NoError(t, err)

	wrappedRSAPrivKeyStr, err := wrapKeyWithAESGCM([]byte(rsaPrivKey), rootKey)
	require.NoError(t, err)

	ecKey, err := generateECKeyAndPEM(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	ecPrivKey, err := ecKey.PrivateKeyInPemFormat()
	require.NoError(t, err)
	ecPubKey, err := ecKey.PublicKeyInPemFormat()
	require.NoError(t, err)

	wrappedECPrivKeyStr, err := wrapKeyWithAESGCM([]byte(ecPrivKey), rootKey)
	require.NoError(t, err)

	bm, err := NewBasicManager(log, testCache, rootKeyHex)
	require.NoError(t, err)

	samplePayload := []byte("secret payload16") // 16 bytes for valid AES key

	t.Run("successful RSA decryption", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.MID = "rsa-kid-decrypt"
		mockDetails.MAlgorithm = AlgorithmRSA2048
		mockDetails.MPrivateKey = &policy.PrivateKeyCtx{WrappedKey: wrappedRSAPrivKeyStr}

		// Set up mock expectations
		mockDetails.On("ID").Return(trust.KeyIdentifier(mockDetails.MID))
		mockDetails.On("Algorithm").Return(mockDetails.MAlgorithm)
		mockDetails.On("ExportPrivateKey").Return(&trust.PrivateKey{WrappingKeyID: trust.KeyIdentifier(mockDetails.MPrivateKey.GetKeyId()), WrappedKey: mockDetails.MPrivateKey.GetWrappedKey()}, nil)

		rsaEncryptor, err := ocrypto.NewAsymEncryption(rsaPubKey)
		require.NoError(t, err)
		ciphertext, err := rsaEncryptor.Encrypt(samplePayload)
		require.NoError(t, err)

		protectedKey, err := bm.Decrypt(t.Context(), mockDetails, ciphertext, nil)
		require.NoError(t, err)
		require.NotNil(t, protectedKey)

		// Use noOpEncapsulator to get raw key data for testing
		noOpEnc := &noOpEncapsulator{}
		decryptedPayload, err := protectedKey.Export(noOpEnc)
		require.NoError(t, err)
		assert.Equal(t, samplePayload, decryptedPayload)
	})

	t.Run("successful EC decryption", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.MID = "ec-kid-decrypt"
		mockDetails.MAlgorithm = AlgorithmECP256R1
		mockDetails.MPrivateKey = &policy.PrivateKeyCtx{WrappedKey: wrappedECPrivKeyStr}

		// Set up mock expectations
		mockDetails.On("ID").Return(trust.KeyIdentifier(mockDetails.MID))
		mockDetails.On("Algorithm").Return(mockDetails.MAlgorithm)
		mockDetails.On("ExportPrivateKey").Return(&trust.PrivateKey{WrappingKeyID: trust.KeyIdentifier(mockDetails.MPrivateKey.GetKeyId()), WrappedKey: mockDetails.MPrivateKey.GetWrappedKey()}, nil)

		ecEncryptor, err := ocrypto.FromPublicPEM(ecPubKey)
		require.NoError(t, err)
		ciphertext, err := ecEncryptor.Encrypt(samplePayload)
		require.NoError(t, err)
		ephemeralPublicKey := ecEncryptor.EphemeralKey()

		protectedKey, err := bm.Decrypt(t.Context(), mockDetails, ciphertext, ephemeralPublicKey)
		require.NoError(t, err)
		require.NotNil(t, protectedKey)

		// Use noOpEncapsulator to get raw key data for testing
		noOpEnc := &noOpEncapsulator{}
		decryptedPayload, err := protectedKey.Export(noOpEnc)
		require.NoError(t, err)
		assert.Equal(t, samplePayload, decryptedPayload)
	})

	t.Run("fail ExportPrivateKey", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.On("ID").Return(trust.KeyIdentifier("fail-export"))
		mockDetails.On("ExportPrivateKey").Return(nil, errors.New("export failed"))

		_, err := bm.Decrypt(t.Context(), mockDetails, []byte("ct"), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get private key")
	})

	t.Run("fail unwrap", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.MID = "fail-unwrap-decrypt"
		mockDetails.MAlgorithm = AlgorithmRSA2048
		mockDetails.MPrivateKey = &policy.PrivateKeyCtx{WrappedKey: "invalid-base64-for-unwrap"}

		// Set up mock expectations for ExportPrivateKey to return a valid wrapped key
		// so that the unwrap logic can then fail as intended by this test.
		mockDetails.On("ID").Return(trust.KeyIdentifier(mockDetails.MID))
		mockDetails.On("Algorithm").Return(mockDetails.MAlgorithm)
		mockDetails.On("ExportPrivateKey").Return(&trust.PrivateKey{WrappingKeyID: trust.KeyIdentifier(mockDetails.MPrivateKey.GetKeyId()), WrappedKey: mockDetails.MPrivateKey.GetWrappedKey()}, nil)

		_, err = bm.Decrypt(t.Context(), mockDetails, []byte("ct"), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unwrap private key")
	})

	t.Run("fail FromPrivatePEM", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.MID = "fail-frompem-decrypt"
		mockDetails.MAlgorithm = AlgorithmRSA2048
		invalidPEMWrapped, _ := wrapKeyWithAESGCM([]byte("-----BEGIN INVALID KEY-----..."), rootKey)
		mockDetails.MPrivateKey = &policy.PrivateKeyCtx{WrappedKey: invalidPEMWrapped}

		mockDetails.On("ID").Return(trust.KeyIdentifier(mockDetails.MID))
		mockDetails.On("Algorithm").Return(mockDetails.MAlgorithm)
		mockDetails.On("ExportPrivateKey").Return(&trust.PrivateKey{WrappingKeyID: trust.KeyIdentifier(mockDetails.MPrivateKey.GetKeyId()), WrappedKey: mockDetails.MPrivateKey.GetWrappedKey()}, nil) // Ensure this mock is correctly set up
		_, err = bm.Decrypt(t.Context(), mockDetails, []byte("ct"), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create decryptor from private PEM")
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.MID = "unsupported-algo-decrypt"
		mockDetails.MAlgorithm = "unknown-algo"
		mockDetails.MPrivateKey = &policy.PrivateKeyCtx{WrappedKey: wrappedRSAPrivKeyStr}

		mockDetails.On("ID").Return(trust.KeyIdentifier(mockDetails.MID))
		mockDetails.On("Algorithm").Return(mockDetails.MAlgorithm)                                                                                                                                     // Corrected: require.NoError
		mockDetails.On("ExportPrivateKey").Return(&trust.PrivateKey{WrappingKeyID: trust.KeyIdentifier(mockDetails.MPrivateKey.GetKeyId()), WrappedKey: mockDetails.MPrivateKey.GetWrappedKey()}, nil) // Ensure this mock is correctly set up
		_, err = bm.Decrypt(t.Context(), mockDetails, []byte("ct"), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm: unknown-algo")
	})
}

func TestBasicManager_DeriveKey(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	rootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	rootKey, _ := hex.DecodeString(rootKeyHex)

	ecKey, err := generateECKeyAndPEM(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	ecPrivKey, err := ecKey.PrivateKeyInPemFormat()
	require.NoError(t, err)

	wrappedECPrivKeyStr, err := wrapKeyWithAESGCM([]byte(ecPrivKey), rootKey)
	require.NoError(t, err)

	bm, err := NewBasicManager(log, testCache, rootKeyHex)
	require.NoError(t, err)

	clientEphemeralECDHKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	// Ensure the public key is in compressed format as expected by ocrypto.UncompressECPubKey
	ecdhPubKey := clientEphemeralECDHKey.PublicKey()
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(ecdhPubKey)
	require.NoError(t, err)
	parsedPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	require.NoError(t, err)
	clientECDSAKey, ok := parsedPubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "failed to convert ecdh.PublicKey to *ecdsa.PublicKey")
	clientEphemeralPublicKeyBytes, err := ocrypto.CompressedECPublicKey(ocrypto.ECCModeSecp256r1, *clientECDSAKey)
	require.NoError(t, err)

	t.Run("successful key derivation", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.MID = "ec-kid-derive"
		mockDetails.MAlgorithm = AlgorithmECP256R1
		mockDetails.MPrivateKey = &policy.PrivateKeyCtx{WrappedKey: wrappedECPrivKeyStr}

		// Set up mock expectations
		mockDetails.On("ID").Return(trust.KeyIdentifier(mockDetails.MID))
		mockDetails.On("Algorithm").Return(mockDetails.MAlgorithm)
		mockDetails.On("ExportPrivateKey").Return(&trust.PrivateKey{WrappingKeyID: trust.KeyIdentifier(mockDetails.MPrivateKey.GetKeyId()), WrappedKey: mockDetails.MPrivateKey.GetWrappedKey()}, nil)

		protectedKey, err := bm.DeriveKey(t.Context(), mockDetails, clientEphemeralPublicKeyBytes, elliptic.P256())
		require.NoError(t, err)
		require.NotNil(t, protectedKey)

		ecdhPrivKey, err := ocrypto.ECPrivateKeyFromPem([]byte(ecPrivKey)) // ECDH private key
		require.NoError(t, err)

		// We need to compute the shared secret using the private key and the client ephemeral public key
		clientEphemeralECDSAPubKey, err := ocrypto.UncompressECPubKey(elliptic.P256(), clientEphemeralPublicKeyBytes)
		require.NoError(t, err)
		clientECDHPublicKey, err := ocrypto.ConvertToECDHPublicKey(clientEphemeralECDSAPubKey)
		require.NoError(t, err)

		expectedSharedSecret, err := ocrypto.ComputeECDHKeyFromECDHKeys(clientECDHPublicKey, ecdhPrivKey)
		require.NoError(t, err)
		expectedDerivedKey, err := ocrypto.CalculateHKDF(TDFSalt(), expectedSharedSecret)
		require.NoError(t, err)

		// Use noOpEncapsulator to get raw key data for testing
		noOpEnc := &noOpEncapsulator{}
		actualDerivedKey, err := protectedKey.Export(noOpEnc)
		require.NoError(t, err)
		assert.Equal(t, expectedDerivedKey, actualDerivedKey)
	})

	t.Run("fail ExportPrivateKey for DeriveKey", func(t *testing.T) {
		mockDetails := new(MockKeyDetails)
		mockDetails.On("ID").Return(trust.KeyIdentifier("fail-export-derive"))
		mockDetails.On("ExportPrivateKey").Return(nil, errors.New("export failed derive"))

		_, err := bm.DeriveKey(t.Context(), mockDetails, clientEphemeralPublicKeyBytes, elliptic.P256())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get private key")
	})
}

func TestBasicManager_GenerateECSessionKey(t *testing.T) {
	log := logger.CreateTestLogger()
	testCache := newTestCache(t, log)
	rootKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	bm, err := NewBasicManager(log, testCache, rootKeyHex)
	require.NoError(t, err)

	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientPubKeyBytes, err := x509.MarshalPKIXPublicKey(&clientPrivKey.PublicKey)
	require.NoError(t, err)
	clientPubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: clientPubKeyBytes})

	t.Run("successful session key generation", func(t *testing.T) {
		encapsulator, err := bm.GenerateECSessionKey(t.Context(), string(clientPubKeyPEM))
		require.NoError(t, err)
		require.NotNil(t, encapsulator)

		ephemKey := encapsulator.EphemeralKey()
		assert.NotEmpty(t, ephemKey, "Ephemeral key should be generated")

		sampleData := []byte("test data for encapsulation")
		encryptedData, err := encapsulator.Encrypt(sampleData)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedData)
	})

	t.Run("fail with invalid ephemeral public key PEM", func(t *testing.T) {
		_, err := bm.GenerateECSessionKey(t.Context(), "invalid PEM data")
		require.Error(t, err)
	})
}
