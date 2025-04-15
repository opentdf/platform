package cryptoproviders

import (
	"context"
	"crypto"
	"encoding/json" // Added for marshalling PrivateKeyCtx
	"fmt"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockCryptoProvider is a mock implementation of the CryptoProvider interface
type MockCryptoProvider struct {
	mock.Mock
}

func (m *MockCryptoProvider) Identifier() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockCryptoProvider) EncryptSymmetric(ctx context.Context, key []byte, data []byte) ([]byte, error) {
	args := m.Called(ctx, key, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoProvider) DecryptSymmetric(ctx context.Context, key []byte, cipherText []byte) ([]byte, error) {
	args := m.Called(ctx, key, cipherText)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoProvider) EncryptAsymmetric(ctx context.Context, opts EncryptOpts) (cipherText []byte, ephemeralKey []byte, err error) {
	args := m.Called(ctx, opts)
	ct := args.Get(0)
	ek := args.Get(1)
	e := args.Error(2)

	var ctBytes []byte
	if ct != nil {
		ctBytes = ct.([]byte)
	}
	var ekBytes []byte
	if ek != nil {
		ekBytes = ek.([]byte)
	}

	return ctBytes, ekBytes, e
}

func (m *MockCryptoProvider) DecryptAsymmetric(ctx context.Context, opts DecryptOpts) ([]byte, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// Basic tests for KeyFormat and KeyRef
func TestKeyFormat(t *testing.T) {
	raw := []byte("testkey")
	kf := NewKeyFormat(raw)
	require.Equal(t, raw, kf.Raw)
	require.Equal(t, "pem", kf.Format)
}

func TestKeyRef(t *testing.T) {
	raw := []byte("testkey")
	algo := policy.Algorithm_ALGORITHM_RSA_2048
	kr := NewKeyRef(raw, algo)

	require.Equal(t, raw, kr.GetRawBytes())
	require.Equal(t, algo, kr.Algorithm)
	require.True(t, kr.IsRSA())
	require.False(t, kr.IsEC())
	require.Equal(t, 256, kr.GetExpectedRSAKeySize())

	krEC := NewKeyRef([]byte("eckey"), policy.Algorithm_ALGORITHM_EC_P256)
	require.False(t, krEC.IsRSA())
	require.True(t, krEC.IsEC())
	require.Equal(t, 0, krEC.GetExpectedRSAKeySize()) // Not RSA
}

func TestKeyRef_Validate(t *testing.T) {
	// Valid RSA 2048
	validRSA2048 := make([]byte, 256)
	krRSA2048 := NewKeyRef(validRSA2048, policy.Algorithm_ALGORITHM_RSA_2048)
	require.NoError(t, krRSA2048.Validate())

	// Invalid RSA 2048 length
	invalidRSA2048 := make([]byte, 255)
	krInvalidRSA2048 := NewKeyRef(invalidRSA2048, policy.Algorithm_ALGORITHM_RSA_2048)
	err := krInvalidRSA2048.Validate()
	require.Error(t, err)
	require.IsType(t, ErrInvalidKeyFormat{}, err)

	// Valid EC P256 compressed
	validECP256Comp := make([]byte, 33)
	krECP256Comp := NewKeyRef(validECP256Comp, policy.Algorithm_ALGORITHM_EC_P256)
	require.NoError(t, krECP256Comp.Validate())

	// Valid EC P256 uncompressed
	validECP256Uncomp := make([]byte, 65)
	krECP256Uncomp := NewKeyRef(validECP256Uncomp, policy.Algorithm_ALGORITHM_EC_P256)
	require.NoError(t, krECP256Uncomp.Validate())

	// Invalid EC P256 length
	invalidECP256 := make([]byte, 64)
	krInvalidECP256 := NewKeyRef(invalidECP256, policy.Algorithm_ALGORITHM_EC_P256)
	errEC := krInvalidECP256.Validate()
	require.Error(t, errEC)
	require.IsType(t, ErrInvalidKeyFormat{}, errEC)

	// Nil key
	krNil := NewKeyRef(nil, policy.Algorithm_ALGORITHM_RSA_2048)
	errNil := krNil.Validate()
	require.Error(t, errNil)
	require.IsType(t, ErrInvalidKeyFormat{}, errNil)
	require.Contains(t, errNil.Error(), "key bytes cannot be nil")

	// Unsupported RSA
	krUnsupportedRSA := NewKeyRef([]byte("somekey"), policy.Algorithm_ALGORITHM_UNSPECIFIED) // Treat as RSA for size check
	krUnsupportedRSA.Algorithm = policy.Algorithm_ALGORITHM_RSA_4096 + 10                    // Fake RSA type
	// Manually set IsRSA to true for testing the size check branch
	// This is a bit hacky, ideally IsRSA would handle ALGORITHM_UNSPECIFIED differently
	// For now, we assume GetExpectedRSAKeySize returns 0 for non-explicit RSA types
	require.Equal(t, 0, krUnsupportedRSA.GetExpectedRSAKeySize())
	// Since GetExpectedRSAKeySize returns 0, Validate should error if IsRSA is true
	// We can't directly test this path easily without modifying IsRSA or GetExpectedRSAKeySize behavior for unspecified.
	// Let's test the default case in GetExpectedRSAKeySize instead.
	krDefaultRSA := KeyRef{Algorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED}
	require.Equal(t, 0, krDefaultRSA.GetExpectedRSAKeySize())
}

func TestCryptoService_RegistrationAndRetrieval(t *testing.T) {
	mockDefaultProvider := new(MockCryptoProvider)
	mockDefaultProvider.On("Identifier").Return(DefaultProvider)

	cs := NewCryptoService(mockDefaultProvider)
	require.NotNil(t, cs)

	// Test getting the default provider
	p, err := cs.GetProvider(DefaultProvider)
	require.NoError(t, err)
	require.Equal(t, mockDefaultProvider, p)

	// Test registering a new provider
	mockProvider1 := new(MockCryptoProvider)
	mockProvider1.On("Identifier").Return("provider1")
	cs.RegisterProvider(mockProvider1)

	// Test getting the new provider
	p1, err1 := cs.GetProvider("provider1")
	require.NoError(t, err1)
	require.Equal(t, mockProvider1, p1)

	// Test getting a non-existent provider
	_, errNotFound := cs.GetProvider("nonexistent")
	require.Error(t, errNotFound)
	require.IsType(t, ErrProviderNotFound{}, errNotFound)
	require.Equal(t, "crypto provider not found: nonexistent", errNotFound.Error())

	// Test registering a nil provider (should panic)
	require.Panics(t, func() {
		cs.RegisterProvider(nil)
	}, "Registering a nil provider should panic")

	// Test creating service with nil default provider (should panic)
	require.Panics(t, func() {
		NewCryptoService(nil)
	}, "Creating service with nil default provider should panic")
}

func TestCryptoService_EncryptAsymmetric(t *testing.T) {
	ctx := context.Background()
	mockDefaultProvider := new(MockCryptoProvider)
	mockDefaultProvider.On("Identifier").Return(DefaultProvider).Maybe() // Expect Identifier during registration, but don't fail if not called in sub-tests
	mockRemoteProvider := new(MockCryptoProvider)
	mockRemoteProvider.On("Identifier").Return("remote").Maybe() // Expect Identifier during registration

	cs := NewCryptoService(mockDefaultProvider)
	cs.RegisterProvider(mockRemoteProvider)

	data := []byte("plaintext")
	publicKeyBytes := make([]byte, 256) // Dummy RSA 2048 public key
	keyRefLocal := &policy.AsymmetricKey{
		PublicKeyCtx: publicKeyBytes,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefRemote := &policy.AsymmetricKey{
		PublicKeyCtx: publicKeyBytes, // Could be an identifier in real remote scenario
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}
	expectedCipherText := []byte("ciphertext")
	expectedEphemeralKey := []byte("ephemeral")

	// --- Test Cases ---

	// 1. Success: Default provider (Local mode, no provider config)
	t.Run("Success_DefaultProvider", func(t *testing.T) {
		mockDefaultProvider.On("EncryptAsymmetric", ctx, mock.AnythingOfType("cryptoproviders.EncryptOpts")).Return(expectedCipherText, expectedEphemeralKey, nil).Once()
		cipherText, ephemeralKey, err := cs.EncryptAsymmetric(ctx, data, keyRefLocal)
		require.NoError(t, err)
		require.Equal(t, expectedCipherText, cipherText)
		require.Equal(t, expectedEphemeralKey, ephemeralKey)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 2. Success: Specific provider (Remote mode)
	t.Run("Success_RemoteProvider", func(t *testing.T) {
		mockRemoteProvider.On("EncryptAsymmetric", ctx, mock.AnythingOfType("cryptoproviders.EncryptOpts")).Return(expectedCipherText, expectedEphemeralKey, nil).Once()
		cipherText, ephemeralKey, err := cs.EncryptAsymmetric(ctx, data, keyRefRemote)
		require.NoError(t, err)
		require.Equal(t, expectedCipherText, cipherText)
		require.Equal(t, expectedEphemeralKey, ephemeralKey)
		mockRemoteProvider.AssertExpectations(t)
	})

	// 3. Error: Nil Key Reference
	t.Run("Error_NilKeyRef", func(t *testing.T) {
		_, _, err := cs.EncryptAsymmetric(ctx, data, nil)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "key reference is nil")
	})

	// 4. Error: Empty Data
	t.Run("Error_EmptyData", func(t *testing.T) {
		_, _, err := cs.EncryptAsymmetric(ctx, []byte{}, keyRefLocal)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "empty data")
	})

	// 5. Error: Provider Not Found (Remote mode)
	t.Run("Error_ProviderNotFound", func(t *testing.T) {
		keyRefBadRemote := &policy.AsymmetricKey{
			PublicKeyCtx: publicKeyBytes,
			KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
			ProviderConfig: &policy.KeyProviderConfig{
				Name: "nonexistent", // This provider is not registered
			},
		}
		_, _, err := cs.EncryptAsymmetric(ctx, data, keyRefBadRemote)
		require.Error(t, err)
		require.IsType(t, ErrProviderNotFound{}, err)
	})

	// 6. Error: Provider Encryption Failure (Default)
	t.Run("Error_ProviderEncryptFailure_Default", func(t *testing.T) {
		expectedErr := fmt.Errorf("provider encryption failed")
		mockDefaultProvider.On("EncryptAsymmetric", ctx, mock.AnythingOfType("cryptoproviders.EncryptOpts")).Return(nil, nil, expectedErr).Once()
		_, _, err := cs.EncryptAsymmetric(ctx, data, keyRefLocal)
		require.Error(t, err)
		require.Equal(t, expectedErr, err) // Should return the provider's error directly
		mockDefaultProvider.AssertExpectations(t)
	})

	// 7. Success: With RSA Options
	t.Run("Success_WithOptions_RSA", func(t *testing.T) {
		testHash := crypto.SHA512
		mockDefaultProvider.On("EncryptAsymmetric", ctx, mock.MatchedBy(func(opts EncryptOpts) bool {
			return opts.Hash == testHash && opts.KeyRef.Algorithm == keyRefLocal.GetKeyAlgorithm()
		})).Return(expectedCipherText, expectedEphemeralKey, nil).Once()

		cipherText, ephemeralKey, err := cs.EncryptAsymmetric(ctx, data, keyRefLocal, WithRSAHash(testHash))
		require.NoError(t, err)
		require.Equal(t, expectedCipherText, cipherText)
		require.Equal(t, expectedEphemeralKey, ephemeralKey)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 8. Success: With EC Options (using default provider for simplicity)
	t.Run("Success_WithOptions_EC", func(t *testing.T) {
		ecKeyRefLocal := &policy.AsymmetricKey{
			PublicKeyCtx: make([]byte, 65), // Dummy EC P256 public key
			KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
			KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		}
		testEphemeral := []byte("test-ephemeral")
		mockDefaultProvider.On("EncryptAsymmetric", ctx, mock.MatchedBy(func(opts EncryptOpts) bool {
			return opts.KeyRef.Algorithm == ecKeyRefLocal.GetKeyAlgorithm() && string(opts.EphemeralKey) == string(testEphemeral)
		})).Return(expectedCipherText, expectedEphemeralKey, nil).Once()

		cipherText, ephemeralKey, err := cs.EncryptAsymmetric(ctx, data, ecKeyRefLocal, WithECEphemeralKey(testEphemeral))
		require.NoError(t, err)
		require.Equal(t, expectedCipherText, cipherText)
		require.Equal(t, expectedEphemeralKey, ephemeralKey)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 9. Error: Applying Options Failure
	t.Run("Error_ApplyOptionsFailure", func(t *testing.T) {
		badOption := func(c *rsaConfig) error {
			return fmt.Errorf("bad option config")
		}
		_, _, err := cs.EncryptAsymmetric(ctx, data, keyRefLocal, RSAOptions(badOption))
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "applying RSA options")
		require.Contains(t, err.Error(), "bad option config")
	})

}

func TestCryptoService_DecryptAsymmetric(t *testing.T) {
	ctx := context.Background()
	mockDefaultProvider := new(MockCryptoProvider)
	mockDefaultProvider.On("Identifier").Return(DefaultProvider).Maybe()
	mockRemoteProvider := new(MockCryptoProvider)
	mockRemoteProvider.On("Identifier").Return("remote").Maybe()
	mockKekProvider := new(MockCryptoProvider) // Provider for Mode 2 KEK unwrapping
	mockKekProvider.On("Identifier").Return("kekProvider").Maybe()

	cs := NewCryptoService(mockDefaultProvider)
	cs.RegisterProvider(mockRemoteProvider)
	cs.RegisterProvider(mockKekProvider)

	// Test Data
	plainText := []byte("plaintext")
	cipherText := []byte("ciphertext")
	wrappedPrivateKey := []byte("wrappedKeyBytes")
	unwrappedPrivateKey := []byte("unwrappedKeyBytes") // Needs to be valid format for default provider decrypt
	kek := []byte("keyEncryptionKey")

	// Prepare PrivateKeyCtx JSON
	pkCtx := PrivateKeyCtx{WrappedKey: wrappedPrivateKey}
	pkCtxBytes, err := json.Marshal(pkCtx)
	require.NoError(t, err, "Failed to marshal PrivateKeyCtx for tests")

	// Key References
	keyRefMode1 := &policy.AsymmetricKey{ // LOCAL with KEK from config
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048, // Assume RSA for simplicity
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefMode2 := &policy.AsymmetricKey{ // LOCAL with KEK from Provider
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "kekProvider",
		},
	}
	keyRefMode3 := &policy.AsymmetricKey{ // REMOTE
		PrivateKeyCtx: pkCtxBytes, // In reality, might be a key handle/ID for remote provider
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}

	// --- Test Cases ---

	// 1. Success: Mode 1 (Local with KEK from config)
	t.Run("Success_Mode1_Local_KEK_Config", func(t *testing.T) {
		// Mock default provider for unwrapping
		mockDefaultProvider.On("DecryptSymmetric", ctx, kek, wrappedPrivateKey).Return(unwrappedPrivateKey, nil).Once()
		// Mock default provider for final decryption
		mockDefaultProvider.On("DecryptAsymmetric", ctx, mock.MatchedBy(func(opts DecryptOpts) bool {
			return string(opts.KeyRef.GetRawBytes()) == string(unwrappedPrivateKey) && string(opts.CipherText) == string(cipherText)
		})).Return(plainText, nil).Once()

		decrypted, err := cs.DecryptAsymmetric(ctx, keyRefMode1, cipherText, WithRSAKeK(kek)) // Pass KEK via options
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 2. Success: Mode 2 (Local with KEK from Provider)
	t.Run("Success_Mode2_Local_KEK_Provider", func(t *testing.T) {
		// Mock KEK provider for unwrapping (using DecryptSymmetric)
		// Note: The key passed to DecryptSymmetric for unwrapping in Mode 2 is PrivateKeyCtx itself
		mockKekProvider.On("DecryptSymmetric", ctx, pkCtxBytes, wrappedPrivateKey).Return(unwrappedPrivateKey, nil).Once()
		// Mock default provider for final decryption
		mockDefaultProvider.On("DecryptAsymmetric", ctx, mock.MatchedBy(func(opts DecryptOpts) bool {
			return string(opts.KeyRef.GetRawBytes()) == string(unwrappedPrivateKey) && string(opts.CipherText) == string(cipherText)
		})).Return(plainText, nil).Once()

		decrypted, err := cs.DecryptAsymmetric(ctx, keyRefMode2, cipherText) // KEK is handled by kekProvider
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
		mockKekProvider.AssertExpectations(t)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 3. Success: Mode 3 (Remote)
	t.Run("Success_Mode3_Remote", func(t *testing.T) {
		// Mock remote provider for decryption
		mockRemoteProvider.On("DecryptAsymmetric", ctx, mock.MatchedBy(func(opts DecryptOpts) bool {
			// KeyRef passed to remote provider uses PrivateKeyCtx directly
			return string(opts.KeyRef.GetRawBytes()) == string(pkCtxBytes) && string(opts.CipherText) == string(cipherText)
		})).Return(plainText, nil).Once()

		decrypted, err := cs.DecryptAsymmetric(ctx, keyRefMode3, cipherText)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
		mockRemoteProvider.AssertExpectations(t)
	})

	// --- Error Cases ---

	// 4. Error: Nil Key Reference
	t.Run("Error_NilKeyRef", func(t *testing.T) {
		_, err := cs.DecryptAsymmetric(ctx, nil, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "key reference is nil")
	})

	// 5. Error: Empty Ciphertext
	t.Run("Error_EmptyCiphertext", func(t *testing.T) {
		_, err := cs.DecryptAsymmetric(ctx, keyRefMode1, []byte{})
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "empty ciphertext")
	})

	// 6. Error: Invalid PrivateKeyCtx JSON
	t.Run("Error_InvalidPkCtxJSON", func(t *testing.T) {
		keyRefBadJSON := &policy.AsymmetricKey{
			PrivateKeyCtx: []byte("{invalid json"),
			KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
			KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		}
		_, err := cs.DecryptAsymmetric(ctx, keyRefBadJSON, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "failed to unmarshal private key context")
	})

	// 7. Error: Mode 1 - KEK Missing
	t.Run("Error_Mode1_KEK_Missing", func(t *testing.T) {
		_, err := cs.DecryptAsymmetric(ctx, keyRefMode1, cipherText) // No KEK option provided
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "KEK not set")
	})

	// 8. Error: Mode 1 - Local Unwrapping Failure
	t.Run("Error_Mode1_LocalUnwrapFail", func(t *testing.T) {
		unwrapErr := fmt.Errorf("local unwrap failed")
		mockDefaultProvider.On("DecryptSymmetric", ctx, kek, wrappedPrivateKey).Return(nil, unwrapErr).Once()

		_, err := cs.DecryptAsymmetric(ctx, keyRefMode1, cipherText, WithRSAKeK(kek))
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "local key unwrapping")
		require.ErrorIs(t, err, unwrapErr)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 9. Error: Mode 2 - Provider Not Found
	t.Run("Error_Mode2_ProviderNotFound", func(t *testing.T) {
		keyRefMode2BadProvider := &policy.AsymmetricKey{
			PrivateKeyCtx: pkCtxBytes,
			KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
			KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
			ProviderConfig: &policy.KeyProviderConfig{
				Name: "nonexistentKekProvider",
			},
		}
		_, err := cs.DecryptAsymmetric(ctx, keyRefMode2BadProvider, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrProviderNotFound{}, err)
	})

	// 10. Error: Mode 2 - Provider Unwrapping Failure
	t.Run("Error_Mode2_ProviderUnwrapFail", func(t *testing.T) {
		unwrapErr := fmt.Errorf("provider unwrap failed")
		mockKekProvider.On("DecryptSymmetric", ctx, pkCtxBytes, wrappedPrivateKey).Return(nil, unwrapErr).Once()

		_, err := cs.DecryptAsymmetric(ctx, keyRefMode2, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "provider key unwrapping")
		require.ErrorIs(t, err, unwrapErr)
		mockKekProvider.AssertExpectations(t)
	})

	// 11. Error: Mode 1/2 - Default Provider Decryption Failure
	t.Run("Error_Mode1_DefaultDecryptFail", func(t *testing.T) {
		decryptErr := fmt.Errorf("default decrypt failed")
		// Mock successful unwrap
		mockDefaultProvider.On("DecryptSymmetric", ctx, kek, wrappedPrivateKey).Return(unwrappedPrivateKey, nil).Once()
		// Mock failed decrypt
		mockDefaultProvider.On("DecryptAsymmetric", ctx, mock.AnythingOfType("cryptoproviders.DecryptOpts")).Return(nil, decryptErr).Once()

		_, err := cs.DecryptAsymmetric(ctx, keyRefMode1, cipherText, WithRSAKeK(kek))
		require.Error(t, err)
		// The error from the provider's DecryptAsymmetric should be returned directly
		require.Equal(t, decryptErr, err)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 12. Error: Mode 3 - Provider Not Found
	t.Run("Error_Mode3_ProviderNotFound", func(t *testing.T) {
		keyRefMode3BadProvider := &policy.AsymmetricKey{
			PrivateKeyCtx: pkCtxBytes,
			KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
			KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
			ProviderConfig: &policy.KeyProviderConfig{
				Name: "nonexistentRemoteProvider",
			},
		}
		_, err := cs.DecryptAsymmetric(ctx, keyRefMode3BadProvider, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrProviderNotFound{}, err)
	})

	// 13. Error: Mode 3 - Remote Provider Decryption Failure
	t.Run("Error_Mode3_RemoteDecryptFail", func(t *testing.T) {
		decryptErr := fmt.Errorf("remote decrypt failed")
		mockRemoteProvider.On("DecryptAsymmetric", ctx, mock.AnythingOfType("cryptoproviders.DecryptOpts")).Return(nil, decryptErr).Once()

		_, err := cs.DecryptAsymmetric(ctx, keyRefMode3, cipherText)
		require.Error(t, err)
		// The error from the provider's DecryptAsymmetric should be returned directly
		require.Equal(t, decryptErr, err)
		mockRemoteProvider.AssertExpectations(t)
	})

	// 14. Error: Unsupported Key Mode
	t.Run("Error_UnsupportedKeyMode", func(t *testing.T) {
		keyRefUnsupported := &policy.AsymmetricKey{
			PrivateKeyCtx: pkCtxBytes,
			KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
			KeyMode:       policy.KeyMode_KEY_MODE_UNSPECIFIED, // Or any other invalid mode
		}
		_, err := cs.DecryptAsymmetric(ctx, keyRefUnsupported, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "unsupported key mode")
	})

}
func TestCryptoService_EncryptSymmetric(t *testing.T) {
	ctx := context.Background()
	mockDefaultProvider := new(MockCryptoProvider)
	mockDefaultProvider.On("Identifier").Return(DefaultProvider).Maybe()
	mockRemoteProvider := new(MockCryptoProvider)
	mockRemoteProvider.On("Identifier").Return("remote").Maybe()

	cs := NewCryptoService(mockDefaultProvider)
	cs.RegisterProvider(mockRemoteProvider)

	data := []byte("plaintext data")
	rawKey := []byte("raw-symmetric-key")         // For Mode 1
	keyID := []byte("remote-key-id")              // For Mode 3 (provider handles this)
	wrappedKey := []byte("wrapped-symmetric-key") // For Mode 2 (not supported for encrypt)
	expectedCipherText := []byte("symmetric-ciphertext")

	// Key References
	keyRefMode1 := &policy.SymmetricKey{ // LOCAL (Mode 1)
		KeyCtx:  rawKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefMode2 := &policy.SymmetricKey{ // LOCAL with Provider Config (Mode 2 - Not supported for Encrypt)
		KeyCtx:  wrappedKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "someProvider", // Doesn't matter which provider
		},
	}
	keyRefMode3 := &policy.SymmetricKey{ // REMOTE (Mode 3)
		KeyCtx:  keyID,
		KeyMode: policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}

	// --- Test Cases ---

	// 1. Success: Mode 1 (Local) - Uses Default Provider
	t.Run("Success_Mode1_Local", func(t *testing.T) {
		mockDefaultProvider.On("EncryptSymmetric", ctx, rawKey, data).Return(expectedCipherText, nil).Once()
		cipherText, err := cs.EncryptSymmetric(ctx, keyRefMode1, data)
		require.NoError(t, err)
		require.Equal(t, expectedCipherText, cipherText)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 2. Success: Mode 3 (Remote) - Uses Specified Provider
	t.Run("Success_Mode3_Remote", func(t *testing.T) {
		mockRemoteProvider.On("EncryptSymmetric", ctx, keyID, data).Return(expectedCipherText, nil).Once()
		cipherText, err := cs.EncryptSymmetric(ctx, keyRefMode3, data)
		require.NoError(t, err)
		require.Equal(t, expectedCipherText, cipherText)
		mockRemoteProvider.AssertExpectations(t)
	})

	// --- Error Cases ---

	// 3. Error: Mode 2 (Local with Provider Config) - Not Supported
	t.Run("Error_Mode2_NotSupported", func(t *testing.T) {
		_, err := cs.EncryptSymmetric(ctx, keyRefMode2, data)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "symmetric encryption in local mode with provider config (Mode 2) is not supported")
	})

	// 4. Error: Nil Key Reference
	t.Run("Error_NilKeyRef", func(t *testing.T) {
		_, err := cs.EncryptSymmetric(ctx, nil, data)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "symmetric key reference is nil")
	})

	// 5. Error: Empty Key Context
	t.Run("Error_EmptyKeyCtx", func(t *testing.T) {
		keyRefEmptyCtx := &policy.SymmetricKey{KeyCtx: []byte{}, KeyMode: policy.KeyMode_KEY_MODE_LOCAL}
		_, err := cs.EncryptSymmetric(ctx, keyRefEmptyCtx, data)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "symmetric key context is nil/empty")
	})

	// 6. Error: Empty Data
	t.Run("Error_EmptyData", func(t *testing.T) {
		_, err := cs.EncryptSymmetric(ctx, keyRefMode1, []byte{})
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "empty data")
	})

	// 7. Error: Mode 3 - Provider Config Missing
	t.Run("Error_Mode3_ProviderConfigMissing", func(t *testing.T) {
		keyRefMode3NoConfig := &policy.SymmetricKey{KeyCtx: keyID, KeyMode: policy.KeyMode_KEY_MODE_REMOTE, ProviderConfig: nil}
		_, err := cs.EncryptSymmetric(ctx, keyRefMode3NoConfig, data)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "provider config missing for remote key mode")
	})

	// 8. Error: Mode 3 - Provider Not Found
	t.Run("Error_Mode3_ProviderNotFound", func(t *testing.T) {
		keyRefMode3BadProvider := &policy.SymmetricKey{
			KeyCtx:         keyID,
			KeyMode:        policy.KeyMode_KEY_MODE_REMOTE,
			ProviderConfig: &policy.KeyProviderConfig{Name: "nonexistent"},
		}
		_, err := cs.EncryptSymmetric(ctx, keyRefMode3BadProvider, data)
		require.Error(t, err)
		require.IsType(t, ErrProviderNotFound{}, err)
	})

	// 9. Error: Mode 1 - Default Provider Failure
	t.Run("Error_Mode1_ProviderFailure", func(t *testing.T) {
		providerErr := fmt.Errorf("default provider failed")
		mockDefaultProvider.On("EncryptSymmetric", ctx, rawKey, data).Return(nil, providerErr).Once()
		_, err := cs.EncryptSymmetric(ctx, keyRefMode1, data)
		require.Error(t, err)
		require.Equal(t, providerErr, err) // Should return provider's error directly
		mockDefaultProvider.AssertExpectations(t)
	})

	// 10. Error: Mode 3 - Remote Provider Failure
	t.Run("Error_Mode3_ProviderFailure", func(t *testing.T) {
		providerErr := fmt.Errorf("remote provider failed")
		mockRemoteProvider.On("EncryptSymmetric", ctx, keyID, data).Return(nil, providerErr).Once()
		_, err := cs.EncryptSymmetric(ctx, keyRefMode3, data)
		require.Error(t, err)
		require.Equal(t, providerErr, err) // Should return provider's error directly
		mockRemoteProvider.AssertExpectations(t)
	})

	// 11. Error: Unsupported Key Mode
	t.Run("Error_UnsupportedKeyMode", func(t *testing.T) {
		keyRefUnsupported := &policy.SymmetricKey{KeyCtx: rawKey, KeyMode: policy.KeyMode_KEY_MODE_UNSPECIFIED}
		_, err := cs.EncryptSymmetric(ctx, keyRefUnsupported, data)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "unsupported key mode")
	})
}

func TestCryptoService_DecryptSymmetric(t *testing.T) {
	ctx := context.Background()
	mockDefaultProvider := new(MockCryptoProvider)
	mockDefaultProvider.On("Identifier").Return(DefaultProvider).Maybe()
	mockRemoteProvider := new(MockCryptoProvider)
	mockRemoteProvider.On("Identifier").Return("remote").Maybe()
	mockKekProvider := new(MockCryptoProvider) // Provider for Mode 2 KEK unwrapping
	mockKekProvider.On("Identifier").Return("kekProvider").Maybe()

	cs := NewCryptoService(mockDefaultProvider)
	cs.RegisterProvider(mockRemoteProvider)
	cs.RegisterProvider(mockKekProvider)

	cipherText := []byte("symmetric-ciphertext")
	expectedPlainText := []byte("plaintext data")
	rawKey := []byte("raw-symmetric-key")         // For Mode 1
	keyID := []byte("remote-key-id")              // For Mode 3
	wrappedKey := []byte("wrapped-symmetric-key") // For Mode 2 (KeyCtx holds this)
	unwrappedKey := []byte("unwrapped-key")       // Result of unwrapping in Mode 2

	// Key References
	keyRefMode1 := &policy.SymmetricKey{ // LOCAL (Mode 1)
		KeyCtx:  rawKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefMode2 := &policy.SymmetricKey{ // LOCAL with Provider Config (Mode 2)
		KeyCtx:  wrappedKey, // KeyCtx contains the *wrapped* key
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "kekProvider",
		},
	}
	keyRefMode3 := &policy.SymmetricKey{ // REMOTE (Mode 3)
		KeyCtx:  keyID,
		KeyMode: policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}

	// --- Test Cases ---

	// 1. Success: Mode 1 (Local) - Uses Default Provider
	t.Run("Success_Mode1_Local", func(t *testing.T) {
		mockDefaultProvider.On("DecryptSymmetric", ctx, rawKey, cipherText).Return(expectedPlainText, nil).Once()
		plainText, err := cs.DecryptSymmetric(ctx, keyRefMode1, cipherText)
		require.NoError(t, err)
		require.Equal(t, expectedPlainText, plainText)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 2. Success: Mode 2 (Local with Provider Config) - Unwrap with kekProvider, Decrypt with Default
	t.Run("Success_Mode2_Local_ProviderKEK", func(t *testing.T) {
		// Mock KEK provider for unwrapping (KeyCtx is passed as both key and data for unwrapping)
		mockKekProvider.On("DecryptSymmetric", ctx, wrappedKey, wrappedKey).Return(unwrappedKey, nil).Once()
		// Mock Default provider for final decryption
		mockDefaultProvider.On("DecryptSymmetric", ctx, unwrappedKey, cipherText).Return(expectedPlainText, nil).Once()

		plainText, err := cs.DecryptSymmetric(ctx, keyRefMode2, cipherText)
		require.NoError(t, err)
		require.Equal(t, expectedPlainText, plainText)
		mockKekProvider.AssertExpectations(t)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 3. Success: Mode 3 (Remote) - Uses Specified Provider
	t.Run("Success_Mode3_Remote", func(t *testing.T) {
		mockRemoteProvider.On("DecryptSymmetric", ctx, keyID, cipherText).Return(expectedPlainText, nil).Once()
		plainText, err := cs.DecryptSymmetric(ctx, keyRefMode3, cipherText)
		require.NoError(t, err)
		require.Equal(t, expectedPlainText, plainText)
		mockRemoteProvider.AssertExpectations(t)
	})

	// --- Error Cases ---

	// 4. Error: Nil Key Reference
	t.Run("Error_NilKeyRef", func(t *testing.T) {
		_, err := cs.DecryptSymmetric(ctx, nil, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "symmetric key reference is nil")
	})

	// 5. Error: Empty Key Context
	t.Run("Error_EmptyKeyCtx", func(t *testing.T) {
		keyRefEmptyCtx := &policy.SymmetricKey{KeyCtx: []byte{}, KeyMode: policy.KeyMode_KEY_MODE_LOCAL}
		_, err := cs.DecryptSymmetric(ctx, keyRefEmptyCtx, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrInvalidKeyFormat{}, err)
		require.Contains(t, err.Error(), "symmetric key context is nil/empty")
	})

	// 6. Error: Empty Ciphertext
	t.Run("Error_EmptyCiphertext", func(t *testing.T) {
		_, err := cs.DecryptSymmetric(ctx, keyRefMode1, []byte{})
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "empty ciphertext")
	})

	// 7. Error: Mode 3 - Provider Config Missing
	t.Run("Error_Mode3_ProviderConfigMissing", func(t *testing.T) {
		keyRefMode3NoConfig := &policy.SymmetricKey{KeyCtx: keyID, KeyMode: policy.KeyMode_KEY_MODE_REMOTE, ProviderConfig: nil}
		_, err := cs.DecryptSymmetric(ctx, keyRefMode3NoConfig, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "provider config missing for remote key mode")
	})

	// 8. Error: Mode 3 - Provider Not Found
	t.Run("Error_Mode3_ProviderNotFound", func(t *testing.T) {
		keyRefMode3BadProvider := &policy.SymmetricKey{
			KeyCtx:         keyID,
			KeyMode:        policy.KeyMode_KEY_MODE_REMOTE,
			ProviderConfig: &policy.KeyProviderConfig{Name: "nonexistent"},
		}
		_, err := cs.DecryptSymmetric(ctx, keyRefMode3BadProvider, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrProviderNotFound{}, err)
	})

	// 9. Error: Mode 1 - Default Provider Failure
	t.Run("Error_Mode1_ProviderFailure", func(t *testing.T) {
		providerErr := fmt.Errorf("default provider failed")
		mockDefaultProvider.On("DecryptSymmetric", ctx, rawKey, cipherText).Return(nil, providerErr).Once()
		_, err := cs.DecryptSymmetric(ctx, keyRefMode1, cipherText)
		require.Error(t, err)
		require.Equal(t, providerErr, err) // Should return provider's error directly
		mockDefaultProvider.AssertExpectations(t)
	})

	// 10. Error: Mode 2 - KEK Provider Not Found
	t.Run("Error_Mode2_KEKProviderNotFound", func(t *testing.T) {
		keyRefMode2BadProvider := &policy.SymmetricKey{
			KeyCtx:         wrappedKey,
			KeyMode:        policy.KeyMode_KEY_MODE_LOCAL,
			ProviderConfig: &policy.KeyProviderConfig{Name: "nonexistentKekProvider"},
		}
		_, err := cs.DecryptSymmetric(ctx, keyRefMode2BadProvider, cipherText)
		require.Error(t, err)
		// Note: The error message includes the provider name and wraps the original ErrProviderNotFound
		require.Contains(t, err.Error(), "failed to get unwrapping provider 'nonexistentKekProvider'")
		require.ErrorAs(t, err, new(ErrProviderNotFound))
	})

	// 11. Error: Mode 2 - KEK Provider Unwrapping Failure
	t.Run("Error_Mode2_KEKProviderUnwrapFailure", func(t *testing.T) {
		unwrapErr := fmt.Errorf("kek provider unwrap failed")
		mockKekProvider.On("DecryptSymmetric", ctx, wrappedKey, wrappedKey).Return(nil, unwrapErr).Once()
		_, err := cs.DecryptSymmetric(ctx, keyRefMode2, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "provider key unwrapping (symmetric)")
		require.ErrorIs(t, err, unwrapErr)
		mockKekProvider.AssertExpectations(t)
	})

	// 12. Error: Mode 2 - Default Provider Decryption Failure (after successful unwrap)
	t.Run("Error_Mode2_DefaultProviderDecryptFailure", func(t *testing.T) {
		decryptErr := fmt.Errorf("default provider decrypt failed")
		// Mock successful unwrap
		mockKekProvider.On("DecryptSymmetric", ctx, wrappedKey, wrappedKey).Return(unwrappedKey, nil).Once()
		// Mock failed decrypt by default provider
		mockDefaultProvider.On("DecryptSymmetric", ctx, unwrappedKey, cipherText).Return(nil, decryptErr).Once()

		_, err := cs.DecryptSymmetric(ctx, keyRefMode2, cipherText)
		require.Error(t, err)
		require.Equal(t, decryptErr, err) // Should return the default provider's error directly
		mockKekProvider.AssertExpectations(t)
		mockDefaultProvider.AssertExpectations(t)
	})

	// 13. Error: Mode 3 - Remote Provider Failure
	t.Run("Error_Mode3_ProviderFailure", func(t *testing.T) {
		providerErr := fmt.Errorf("remote provider failed")
		mockRemoteProvider.On("DecryptSymmetric", ctx, keyID, cipherText).Return(nil, providerErr).Once()
		_, err := cs.DecryptSymmetric(ctx, keyRefMode3, cipherText)
		require.Error(t, err)
		require.Equal(t, providerErr, err) // Should return provider's error directly
		mockRemoteProvider.AssertExpectations(t)
	})

	// 14. Error: Unsupported Key Mode
	t.Run("Error_UnsupportedKeyMode", func(t *testing.T) {
		keyRefUnsupported := &policy.SymmetricKey{KeyCtx: rawKey, KeyMode: policy.KeyMode_KEY_MODE_UNSPECIFIED}
		_, err := cs.DecryptSymmetric(ctx, keyRefUnsupported, cipherText)
		require.Error(t, err)
		require.IsType(t, ErrOperationFailed{}, err)
		require.Contains(t, err.Error(), "unsupported key mode")
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("ErrProviderNotFound", func(t *testing.T) {
		err := ErrProviderNotFound{ProviderID: "test-provider"}
		require.Equal(t, "crypto provider not found: test-provider", err.Error())
	})

	t.Run("ErrInvalidKeyFormat", func(t *testing.T) {
		err := ErrInvalidKeyFormat{Details: "bad key length"}
		require.Equal(t, "invalid key format: bad key length", err.Error())
	})

	t.Run("ErrOperationFailed", func(t *testing.T) {
		originalErr := fmt.Errorf("underlying issue")
		err := ErrOperationFailed{Op: "test-op", Err: originalErr}
		require.Equal(t, "crypto operation failed: test-op: underlying issue", err.Error())
		require.ErrorIs(t, err, originalErr) // Check unwrapping
		require.Equal(t, originalErr, err.Unwrap())
	})
}

func TestOptions(t *testing.T) {
	t.Run("RSAOptions", func(t *testing.T) {
		cfg := &rsaConfig{}
		kek := []byte("test-kek")
		hash := crypto.SHA512

		err := WithRSAKeK(kek)(cfg)
		require.NoError(t, err)
		require.Equal(t, kek, cfg.kek)

		err = WithRSAHash(hash)(cfg)
		require.NoError(t, err)
		require.Equal(t, hash, cfg.hash)
	})

	t.Run("ECOptions", func(t *testing.T) {
		cfg := &ecConfig{}
		kek := []byte("test-kek-ec")
		ephemeral := []byte("test-ephemeral")

		err := WithECKeK(kek)(cfg)
		require.NoError(t, err)
		require.Equal(t, kek, cfg.kek)

		err = WithECEphemeralKey(ephemeral)(cfg)
		require.NoError(t, err)
		require.Equal(t, ephemeral, cfg.ephemeralKey)
	})
}

// TODO: Add tests for options
