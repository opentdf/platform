package cryptoproviders

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// MockCryptoProvider is a mock implementation of the CryptoProvider interface
type MockCryptoProvider struct {
	mock.Mock
}

func (m *MockCryptoProvider) Identifier() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockCryptoProvider) UnwrapKey(ctx context.Context, pkCtx *PrivateKeyContext, kek []byte) ([]byte, error) {
	args := m.Called(ctx, pkCtx, kek)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
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

// --- Testify Suites ---

// KeyRefSuite groups KeyRef tests (KeyFormat removed as it does not exist)
type KeyRefSuite struct {
	suite.Suite
}

func (s *KeyRefSuite) TestKeyRef() {
	raw := []byte("testkey")
	algo := policy.Algorithm_ALGORITHM_RSA_2048
	kr := KeyRef{Key: raw, Algorithm: algo}

	s.Equal(raw, kr.GetRawBytes())
	s.Equal(algo, kr.Algorithm)
	s.True(kr.IsRSA())
	s.False(kr.IsEC())
	s.Equal(256, kr.GetExpectedKeySize())

	krEC := KeyRef{Key: []byte("eckey"), Algorithm: policy.Algorithm_ALGORITHM_EC_P256}
	s.False(krEC.IsRSA())
	s.True(krEC.IsEC())
	s.Equal(32, krEC.GetExpectedKeySize()) // Not RSA
}

func (s *KeyRefSuite) TestKeyRef_Validate() {
	// Valid RSA 2048
	validRSA2048 := make([]byte, 256)
	krRSA2048 := KeyRef{Key: validRSA2048, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048}
	s.NoError(krRSA2048.Validate())

	// Invalid RSA 2048 length
	invalidRSA2048 := make([]byte, 255)
	krInvalidRSA2048 := KeyRef{Key: invalidRSA2048, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048}
	err := krInvalidRSA2048.Validate()
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)

	// Valid EC P256 compressed
	validECP256Comp := make([]byte, 33)
	krECP256Comp := KeyRef{Key: validECP256Comp, Algorithm: policy.Algorithm_ALGORITHM_EC_P256}
	s.NoError(krECP256Comp.Validate())

	// Valid EC P256 uncompressed
	validECP256Uncomp := make([]byte, 65)
	krECP256Uncomp := KeyRef{Key: validECP256Uncomp, Algorithm: policy.Algorithm_ALGORITHM_EC_P256}
	s.NoError(krECP256Uncomp.Validate())

	// Invalid EC P256 length
	invalidECP256 := make([]byte, 64)
	krInvalidECP256 := KeyRef{Key: invalidECP256, Algorithm: policy.Algorithm_ALGORITHM_EC_P256}
	errEC := krInvalidECP256.Validate()
	s.Error(errEC)
	s.IsType(ErrInvalidKeyFormat{}, errEC)

	// Nil key
	krNil := KeyRef{Key: nil, Algorithm: policy.Algorithm_ALGORITHM_RSA_2048}
	errNil := krNil.Validate()
	s.Error(errNil)
	s.IsType(ErrInvalidKeyFormat{}, errNil)
	s.Contains(errNil.Error(), "key bytes cannot be nil")

	// Unsupported RSA
	krUnsupportedRSA := KeyRef{Key: []byte("somekey"), Algorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED}
	krUnsupportedRSA.Algorithm = policy.Algorithm_ALGORITHM_RSA_4096 + 10
	s.Equal(0, krUnsupportedRSA.GetExpectedKeySize())
	krDefaultRSA := KeyRef{Algorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED}
	s.Equal(0, krDefaultRSA.GetExpectedKeySize())
}

func TestKeyRefSuite(t *testing.T) {
	suite.Run(t, new(KeyRefSuite))
}

// CryptoServiceRegistrationSuite groups registration and retrieval tests
type CryptoServiceRegistrationSuite struct {
	suite.Suite
}

func (s *CryptoServiceRegistrationSuite) TestRegistrationAndRetrieval() {
	mockDefaultProvider := new(MockCryptoProvider)
	mockDefaultProvider.On("Identifier").Return(DefaultProvider)
	cs := NewCryptoService(mockDefaultProvider, logger.CreateTestLogger())
	s.NotNil(cs)

	// Test getting the default provider
	p, err := cs.GetProvider(DefaultProvider)
	s.NoError(err)
	s.Equal(mockDefaultProvider, p)

	// Test registering a new provider
	mockProvider1 := new(MockCryptoProvider)
	mockProvider1.On("Identifier").Return("provider1")
	cs.RegisterProvider(mockProvider1)

	// Test getting the new provider
	p1, err1 := cs.GetProvider("provider1")
	s.NoError(err1)
	s.Equal(mockProvider1, p1)

	// Test getting a non-existent provider
	_, errNotFound := cs.GetProvider("nonexistent")
	s.Error(errNotFound)
	s.IsType(ErrProviderNotFound{}, errNotFound)
	s.Equal("crypto provider not found: nonexistent", errNotFound.Error())

	// Test registering a nil provider (should panic)
	s.Panics(func() {
		cs.RegisterProvider(nil)
	}, "Registering a nil provider should panic")

	// Test creating service with nil default provider (should panic)
	s.Panics(func() {
		NewCryptoService(nil, logger.CreateTestLogger())
	}, "Creating service with nil default provider should panic")
}

func TestCryptoServiceRegistrationSuite(t *testing.T) {
	suite.Run(t, new(CryptoServiceRegistrationSuite))
}

// CryptoServiceAsymmetricSuite groups EncryptAsymmetric and DecryptAsymmetric tests
type CryptoServiceAsymmetricSuite struct {
	suite.Suite
	ctx             context.Context
	mockDefault     *MockCryptoProvider
	mockRemote      *MockCryptoProvider
	mockKekProvider *MockCryptoProvider
	cs              *CryptoService
}

func (s *CryptoServiceAsymmetricSuite) SetupTest() {
	s.ctx = context.Background()
	s.mockDefault = new(MockCryptoProvider)
	s.mockDefault.On("Identifier").Return(DefaultProvider).Maybe()
	s.mockRemote = new(MockCryptoProvider)
	s.mockRemote.On("Identifier").Return("remote").Maybe()
	s.mockKekProvider = new(MockCryptoProvider)
	s.mockKekProvider.On("Identifier").Return("kekProvider").Maybe()
	s.cs = NewCryptoService(s.mockDefault, logger.CreateTestLogger())
	s.cs.RegisterProvider(s.mockRemote)
	s.cs.RegisterProvider(s.mockKekProvider)
}

func (s *CryptoServiceAsymmetricSuite) TearDownTest() {
	s.mockDefault.AssertExpectations(s.T())
	s.mockRemote.AssertExpectations(s.T())
	s.mockKekProvider.AssertExpectations(s.T())
}

func (s *CryptoServiceAsymmetricSuite) TestEncryptAsymmetric() {
	data := []byte("plaintext")
	publicKeyBytes := make([]byte, 256)
	keyRefLocal := &policy.AsymmetricKey{
		PublicKeyCtx: publicKeyBytes,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefRemote := &policy.AsymmetricKey{
		PublicKeyCtx: publicKeyBytes,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}
	expectedCipherText := []byte("ciphertext")
	expectedEphemeralKey := []byte("ephemeral")

	// 1. Success: Default provider (Local mode, no provider config)
	s.mockDefault.On("EncryptAsymmetric", s.ctx, mock.AnythingOfType("cryptoproviders.EncryptOpts")).Return(expectedCipherText, expectedEphemeralKey, nil).Once()
	cipherText, ephemeralKey, err := s.cs.EncryptAsymmetric(s.ctx, data, keyRefLocal)
	s.NoError(err)
	s.Equal(expectedCipherText, cipherText)
	s.Equal(expectedEphemeralKey, ephemeralKey)

	// 2. Success: Specific provider (Remote mode)
	s.mockRemote.On("EncryptAsymmetric", s.ctx, mock.AnythingOfType("cryptoproviders.EncryptOpts")).Return(expectedCipherText, expectedEphemeralKey, nil).Once()
	cipherText, ephemeralKey, err = s.cs.EncryptAsymmetric(s.ctx, data, keyRefRemote)
	s.NoError(err)
	s.Equal(expectedCipherText, cipherText)
	s.Equal(expectedEphemeralKey, ephemeralKey)

	// 3. Error: Nil Key Reference
	_, _, err = s.cs.EncryptAsymmetric(s.ctx, data, nil)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "key reference is nil")

	// 4. Error: Empty Data
	_, _, err = s.cs.EncryptAsymmetric(s.ctx, []byte{}, keyRefLocal)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "empty data")

	// 5. Error: Provider Not Found (Remote mode)
	keyRefBadRemote := &policy.AsymmetricKey{
		PublicKeyCtx: publicKeyBytes,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "nonexistent",
		},
	}
	_, _, err = s.cs.EncryptAsymmetric(s.ctx, data, keyRefBadRemote)
	s.Error(err)
	s.IsType(ErrProviderNotFound{}, err)

	// 6. Error: Provider Encryption Failure (Default)
	expectedErr := fmt.Errorf("provider encryption failed")
	s.mockDefault.On("EncryptAsymmetric", s.ctx, mock.AnythingOfType("cryptoproviders.EncryptOpts")).Return(nil, nil, expectedErr).Once()
	_, _, err = s.cs.EncryptAsymmetric(s.ctx, data, keyRefLocal)
	s.Error(err)
	s.Equal(expectedErr, err)

	// 7. Success: With RSA Options
	testHash := crypto.SHA512
	s.mockDefault.On("EncryptAsymmetric", s.ctx, mock.MatchedBy(func(opts EncryptOpts) bool {
		return opts.Hash == testHash && opts.KeyRef.Algorithm == keyRefLocal.GetKeyAlgorithm()
	})).Return(expectedCipherText, expectedEphemeralKey, nil).Once()
	cipherText, ephemeralKey, err = s.cs.EncryptAsymmetric(s.ctx, data, keyRefLocal, WithHash(testHash))
	s.NoError(err)
	s.Equal(expectedCipherText, cipherText)
	s.Equal(expectedEphemeralKey, ephemeralKey)

	// 8. Success: With EC Options (using default provider for simplicity)
	ecKeyRefLocal := &policy.AsymmetricKey{
		PublicKeyCtx: make([]byte, 65),
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
	}
	testEphemeral := []byte("test-ephemeral")
	s.mockDefault.On("EncryptAsymmetric", s.ctx, mock.MatchedBy(func(opts EncryptOpts) bool {
		return opts.KeyRef.Algorithm == ecKeyRefLocal.GetKeyAlgorithm() && string(opts.EphemeralKey) == string(testEphemeral)
	})).Return(expectedCipherText, expectedEphemeralKey, nil).Once()
	cipherText, ephemeralKey, err = s.cs.EncryptAsymmetric(s.ctx, data, ecKeyRefLocal, WithEphemeralKey(testEphemeral))
	s.NoError(err)
	s.Equal(expectedCipherText, cipherText)
	s.Equal(expectedEphemeralKey, ephemeralKey)

	// 9. Error: Applying Options Failure
	badOption := func(c *config) error {
		return fmt.Errorf("bad option config")
	}
	_, _, err = s.cs.EncryptAsymmetric(s.ctx, data, keyRefLocal, badOption)
	s.Error(err)
	s.Contains(err.Error(), "applying options")
	s.Contains(err.Error(), "bad option config")
}

func (s *CryptoServiceAsymmetricSuite) TestDecryptAsymmetric() {
	plainText := []byte("plaintext")
	cipherText := []byte("ciphertext")
	wrappedPrivateKey := []byte("wrappedKeyBytes")
	unwrappedPrivateKey := []byte("unwrappedKeyBytes")
	kek := []byte("keyEncryptionKey")

	pkCtx := PrivateKeyContext{WrappedKey: wrappedPrivateKey}
	pkCtxBytes, err := json.Marshal(pkCtx)
	s.Require().NoError(err, "Failed to marshal PrivateKeyCtx for tests")

	keyRefMode1 := &policy.AsymmetricKey{
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefMode2 := &policy.AsymmetricKey{
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "kekProvider",
		},
	}
	keyRefMode3 := &policy.AsymmetricKey{
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}

	// 1. Success: Mode 1 (Local with KEK from config)
	s.mockDefault.On("UnwrapKey", s.ctx, mock.AnythingOfType("*cryptoproviders.PrivateKeyContext"), kek).Return(unwrappedPrivateKey, nil).Once()
	s.mockDefault.On("DecryptAsymmetric", s.ctx, mock.MatchedBy(func(opts DecryptOpts) bool {
		return string(opts.KeyRef.GetRawBytes()) == string(unwrappedPrivateKey) && string(opts.CipherText) == string(cipherText)
	})).Return(plainText, nil).Once()
	decrypted, err := s.cs.DecryptAsymmetric(s.ctx, keyRefMode1, cipherText, func(c *config) error { c.KEK = kek; return nil })
	s.NoError(err)
	s.Equal(plainText, decrypted)

	// 2. Success: Mode 2 (Local with KEK from Provider)
	s.mockKekProvider.On("UnwrapKey", s.ctx, mock.AnythingOfType("*cryptoproviders.PrivateKeyContext"), []byte(nil)).Return(unwrappedPrivateKey, nil).Once()
	s.mockDefault.On("DecryptAsymmetric", s.ctx, mock.MatchedBy(func(opts DecryptOpts) bool {
		return string(opts.KeyRef.GetRawBytes()) == string(unwrappedPrivateKey) && string(opts.CipherText) == string(cipherText)
	})).Return(plainText, nil).Once()
	decrypted, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode2, cipherText)
	s.NoError(err)
	s.Equal(plainText, decrypted)

	// 3. Success: Mode 3 (Remote)
	s.mockRemote.On("DecryptAsymmetric", s.ctx, mock.MatchedBy(func(opts DecryptOpts) bool {
		return string(opts.KeyRef.GetRawBytes()) == string(pkCtxBytes) && string(opts.CipherText) == string(cipherText)
	})).Return(plainText, nil).Once()
	decrypted, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode3, cipherText)
	s.NoError(err)
	s.Equal(plainText, decrypted)

	// 4. Error: Nil Key Reference
	_, err = s.cs.DecryptAsymmetric(s.ctx, nil, cipherText)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "key reference is nil")

	// 5. Error: Empty Ciphertext
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode1, []byte{})
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "empty ciphertext")

	// 6. Error: Invalid PrivateKeyCtx JSON
	keyRefBadJSON := &policy.AsymmetricKey{
		PrivateKeyCtx: []byte("{invalid json"),
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
	}
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefBadJSON, cipherText)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "failed to unmarshal private key context")

	// 7. Error: Mode 1 - KEK Missing
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode1, cipherText)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "KEK not set")

	// 8. Error: Mode 1 - Local Unwrapping Failure
	unwrapErr := fmt.Errorf("local unwrap failed")
	s.mockDefault.On("UnwrapKey", s.ctx, mock.AnythingOfType("*cryptoproviders.PrivateKeyContext"), kek).Return(nil, unwrapErr).Once()
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode1, cipherText, func(c *config) error { c.KEK = kek; return nil })
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "local key unwrapping")
	s.ErrorIs(err, unwrapErr)

	// 9. Error: Mode 2 - Provider Not Found
	keyRefMode2BadProvider := &policy.AsymmetricKey{
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "nonexistentKekProvider",
		},
	}
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode2BadProvider, cipherText)
	s.Error(err)
	s.IsType(ErrProviderNotFound{}, err)

	// 10. Error: Mode 2 - Provider Unwrapping Failure
	unwrapErr = fmt.Errorf("provider unwrap failed")
	s.mockKekProvider.On("UnwrapKey", s.ctx, mock.AnythingOfType("*cryptoproviders.PrivateKeyContext"), []byte(nil)).Return(nil, unwrapErr).Once()
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode2, cipherText)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "provider key unwrapping")
	s.ErrorIs(err, unwrapErr)

	// 11. Error: Mode 1/2 - Default Provider Decryption Failure
	decryptErr := fmt.Errorf("default decrypt failed")
	s.mockDefault.On("UnwrapKey", s.ctx, mock.AnythingOfType("*cryptoproviders.PrivateKeyContext"), kek).Return(unwrappedPrivateKey, nil).Once()
	s.mockDefault.On("DecryptAsymmetric", s.ctx, mock.AnythingOfType("cryptoproviders.DecryptOpts")).Return(nil, decryptErr).Once()
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode1, cipherText, func(c *config) error { c.KEK = kek; return nil })
	s.Error(err)
	s.Equal(decryptErr, err)

	// 12. Error: Mode 3 - Provider Not Found
	keyRefMode3BadProvider := &policy.AsymmetricKey{
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "nonexistentRemoteProvider",
		},
	}
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode3BadProvider, cipherText)
	s.Error(err)
	s.IsType(ErrProviderNotFound{}, err)

	// 13. Error: Mode 3 - Remote Provider Decryption Failure
	decryptErr = fmt.Errorf("remote decrypt failed")
	s.mockRemote.On("DecryptAsymmetric", s.ctx, mock.AnythingOfType("cryptoproviders.DecryptOpts")).Return(nil, decryptErr).Once()
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefMode3, cipherText)
	s.Error(err)
	s.Equal(decryptErr, err)

	// 14. Error: Unsupported Key Mode
	keyRefUnsupported := &policy.AsymmetricKey{
		PrivateKeyCtx: pkCtxBytes,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_UNSPECIFIED,
	}
	_, err = s.cs.DecryptAsymmetric(s.ctx, keyRefUnsupported, cipherText)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "unsupported key mode")
}

func TestCryptoServiceAsymmetricSuite(t *testing.T) {
	suite.Run(t, new(CryptoServiceAsymmetricSuite))
}

// CryptoServiceSymmetricSuite groups EncryptSymmetric and DecryptSymmetric tests
type CryptoServiceSymmetricSuite struct {
	suite.Suite
	ctx             context.Context
	mockDefault     *MockCryptoProvider
	mockRemote      *MockCryptoProvider
	mockKekProvider *MockCryptoProvider
	cs              *CryptoService
}

func (s *CryptoServiceSymmetricSuite) SetupTest() {
	s.ctx = context.Background()
	s.mockDefault = new(MockCryptoProvider)
	s.mockDefault.On("Identifier").Return(DefaultProvider).Maybe()
	s.mockRemote = new(MockCryptoProvider)
	s.mockRemote.On("Identifier").Return("remote").Maybe()
	s.mockKekProvider = new(MockCryptoProvider)
	s.mockKekProvider.On("Identifier").Return("kekProvider").Maybe()
	s.cs = NewCryptoService(s.mockDefault, logger.CreateTestLogger())
	s.cs.RegisterProvider(s.mockRemote)
	s.cs.RegisterProvider(s.mockKekProvider)
}

func (s *CryptoServiceSymmetricSuite) TearDownTest() {
	s.mockDefault.AssertExpectations(s.T())
	s.mockRemote.AssertExpectations(s.T())
	s.mockKekProvider.AssertExpectations(s.T())
}

func (s *CryptoServiceSymmetricSuite) TestEncryptSymmetric() {
	data := []byte("plaintext data")
	rawKey := []byte("raw-symmetric-key")
	keyID := []byte("remote-key-id")
	wrappedKey := []byte("wrapped-symmetric-key")
	expectedCipherText := []byte("symmetric-ciphertext")

	keyRefMode1 := &policy.SymmetricKey{
		KeyCtx:  rawKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefMode2 := &policy.SymmetricKey{
		KeyCtx:  wrappedKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "someProvider",
		},
	}
	keyRefMode3 := &policy.SymmetricKey{
		KeyCtx:  keyID,
		KeyMode: policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}

	// 1. Success: Mode 1 (Local) - Uses Default Provider
	s.mockDefault.On("EncryptSymmetric", s.ctx, rawKey, data).Return(expectedCipherText, nil).Once()
	cipherText, err := s.cs.EncryptSymmetric(s.ctx, keyRefMode1, data)
	s.NoError(err)
	s.Equal(expectedCipherText, cipherText)

	// 2. Success: Mode 3 (Remote) - Uses Specified Provider
	s.mockRemote.On("EncryptSymmetric", s.ctx, keyID, data).Return(expectedCipherText, nil).Once()
	cipherText, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode3, data)
	s.NoError(err)
	s.Equal(expectedCipherText, cipherText)

	// 3. Error: Mode 2 (Local with Provider Config) - Not Supported
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode2, data)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "symmetric encryption in local mode with provider config (Mode 2) is not supported")

	// 4. Error: Nil Key Reference
	_, err = s.cs.EncryptSymmetric(s.ctx, nil, data)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "symmetric key reference is nil")

	// 5. Error: Empty Key Context
	keyRefEmptyCtx := &policy.SymmetricKey{KeyCtx: []byte{}, KeyMode: policy.KeyMode_KEY_MODE_LOCAL}
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefEmptyCtx, data)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "symmetric key context is nil/empty")

	// 6. Error: Empty Data
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode1, []byte{})
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "empty data")

	// 7. Error: Mode 3 - Provider Config Missing
	keyRefMode3NoConfig := &policy.SymmetricKey{KeyCtx: keyID, KeyMode: policy.KeyMode_KEY_MODE_REMOTE, ProviderConfig: nil}
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode3NoConfig, data)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "provider config missing for remote key mode")

	// 8. Error: Mode 3 - Provider Not Found
	keyRefMode3BadProvider := &policy.SymmetricKey{
		KeyCtx:         keyID,
		KeyMode:        policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{Name: "nonexistent"},
	}
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode3BadProvider, data)
	s.Error(err)
	s.IsType(ErrProviderNotFound{}, err)

	// 9. Error: Mode 1 - Default Provider Failure
	providerErr := fmt.Errorf("default provider failed")
	s.mockDefault.On("EncryptSymmetric", s.ctx, rawKey, data).Return(nil, providerErr).Once()
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode1, data)
	s.Error(err)
	s.Equal(providerErr, err)

	// 10. Error: Mode 3 - Remote Provider Failure
	providerErr = fmt.Errorf("remote provider failed")
	s.mockRemote.On("EncryptSymmetric", s.ctx, keyID, data).Return(nil, providerErr).Once()
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefMode3, data)
	s.Error(err)
	s.Equal(providerErr, err)

	// 11. Error: Unsupported Key Mode
	keyRefUnsupported := &policy.SymmetricKey{KeyCtx: rawKey, KeyMode: policy.KeyMode_KEY_MODE_UNSPECIFIED}
	_, err = s.cs.EncryptSymmetric(s.ctx, keyRefUnsupported, data)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "unsupported key mode")
}

func (s *CryptoServiceSymmetricSuite) TestDecryptSymmetric() {
	cipherText := []byte("symmetric-ciphertext")
	expectedPlainText := []byte("plaintext data")
	rawKey := []byte("raw-symmetric-key")
	keyID := []byte("remote-key-id")
	wrappedKey := []byte("wrapped-symmetric-key")
	unwrappedKey := []byte("unwrapped-key")

	keyRefMode1 := &policy.SymmetricKey{
		KeyCtx:  rawKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
	}
	keyRefMode2 := &policy.SymmetricKey{
		KeyCtx:  wrappedKey,
		KeyMode: policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "kekProvider",
		},
	}
	keyRefMode3 := &policy.SymmetricKey{
		KeyCtx:  keyID,
		KeyMode: policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{
			Name: "remote",
		},
	}

	// 1. Success: Mode 1 (Local) - Uses Default Provider
	s.mockDefault.On("DecryptSymmetric", s.ctx, rawKey, cipherText).Return(expectedPlainText, nil).Once()
	plainText, err := s.cs.DecryptSymmetric(s.ctx, keyRefMode1, cipherText)
	s.NoError(err)
	s.Equal(expectedPlainText, plainText)

	// 2. Success: Mode 2 (Local with Provider Config) - Unwrap with kekProvider, Decrypt with Default
	s.mockKekProvider.On("DecryptSymmetric", s.ctx, wrappedKey, wrappedKey).Return(unwrappedKey, nil).Once()
	s.mockDefault.On("DecryptSymmetric", s.ctx, unwrappedKey, cipherText).Return(expectedPlainText, nil).Once()
	plainText, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode2, cipherText)
	s.NoError(err)
	s.Equal(expectedPlainText, plainText)

	// 3. Success: Mode 3 (Remote) - Uses Specified Provider
	s.mockRemote.On("DecryptSymmetric", s.ctx, keyID, cipherText).Return(expectedPlainText, nil).Once()
	plainText, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode3, cipherText)
	s.NoError(err)
	s.Equal(expectedPlainText, plainText)

	// 4. Error: Nil Key Reference
	_, err = s.cs.DecryptSymmetric(s.ctx, nil, cipherText)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "symmetric key reference is nil")

	// 5. Error: Empty Key Context
	keyRefEmptyCtx := &policy.SymmetricKey{KeyCtx: []byte{}, KeyMode: policy.KeyMode_KEY_MODE_LOCAL}
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefEmptyCtx, cipherText)
	s.Error(err)
	s.IsType(ErrInvalidKeyFormat{}, err)
	s.Contains(err.Error(), "symmetric key context is nil/empty")

	// 6. Error: Empty Ciphertext
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode1, []byte{})
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "empty ciphertext")

	// 7. Error: Mode 3 - Provider Config Missing
	keyRefMode3NoConfig := &policy.SymmetricKey{KeyCtx: keyID, KeyMode: policy.KeyMode_KEY_MODE_REMOTE, ProviderConfig: nil}
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode3NoConfig, cipherText)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "provider config missing for remote key mode")

	// 8. Error: Mode 3 - Provider Not Found
	keyRefMode3BadProvider := &policy.SymmetricKey{
		KeyCtx:         keyID,
		KeyMode:        policy.KeyMode_KEY_MODE_REMOTE,
		ProviderConfig: &policy.KeyProviderConfig{Name: "nonexistent"},
	}
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode3BadProvider, cipherText)
	s.Error(err)
	s.IsType(ErrProviderNotFound{}, err)

	// 9. Error: Mode 1 - Default Provider Failure
	providerErr := fmt.Errorf("default provider failed")
	s.mockDefault.On("DecryptSymmetric", s.ctx, rawKey, cipherText).Return(nil, providerErr).Once()
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode1, cipherText)
	s.Error(err)
	s.Equal(providerErr, err)

	// 10. Error: Mode 2 - KEK Provider Not Found
	keyRefMode2BadProvider := &policy.SymmetricKey{
		KeyCtx:         wrappedKey,
		KeyMode:        policy.KeyMode_KEY_MODE_LOCAL,
		ProviderConfig: &policy.KeyProviderConfig{Name: "nonexistentKekProvider"},
	}
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode2BadProvider, cipherText)
	s.Error(err)
	s.Contains(err.Error(), "failed to get unwrapping provider 'nonexistentKekProvider'")
	var notFoundErr ErrProviderNotFound
	s.ErrorAs(err, &notFoundErr)

	// 11. Error: Mode 2 - KEK Provider Unwrapping Failure
	unwrapErr := fmt.Errorf("kek provider unwrap failed")
	s.mockKekProvider.On("DecryptSymmetric", s.ctx, wrappedKey, wrappedKey).Return(nil, unwrapErr).Once()
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode2, cipherText)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "provider key unwrapping (symmetric)")
	s.ErrorIs(err, unwrapErr)

	// 12. Error: Mode 2 - Default Provider Decryption Failure (after successful unwrap)
	decryptErr := fmt.Errorf("default provider decrypt failed")
	s.mockKekProvider.On("DecryptSymmetric", s.ctx, wrappedKey, wrappedKey).Return(unwrappedKey, nil).Once()
	s.mockDefault.On("DecryptSymmetric", s.ctx, unwrappedKey, cipherText).Return(nil, decryptErr).Once()
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode2, cipherText)
	s.Error(err)
	s.Equal(decryptErr, err)

	// 13. Error: Mode 3 - Remote Provider Failure
	providerErr = fmt.Errorf("remote provider failed")
	s.mockRemote.On("DecryptSymmetric", s.ctx, keyID, cipherText).Return(nil, providerErr).Once()
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefMode3, cipherText)
	s.Error(err)
	s.Equal(providerErr, err)

	// 14. Error: Unsupported Key Mode
	keyRefUnsupported := &policy.SymmetricKey{KeyCtx: rawKey, KeyMode: policy.KeyMode_KEY_MODE_UNSPECIFIED}
	_, err = s.cs.DecryptSymmetric(s.ctx, keyRefUnsupported, cipherText)
	s.Error(err)
	s.IsType(ErrOperationFailed{}, err)
	s.Contains(err.Error(), "unsupported key mode")
}

func TestCryptoServiceSymmetricSuite(t *testing.T) {
	suite.Run(t, new(CryptoServiceSymmetricSuite))
}

// ErrorTypesSuite groups error type tests
type ErrorTypesSuite struct {
	suite.Suite
}

func (s *ErrorTypesSuite) TestErrProviderNotFound() {
	err := ErrProviderNotFound{ProviderID: "test-provider"}
	s.Equal("crypto provider not found: test-provider", err.Error())
}

func (s *ErrorTypesSuite) TestErrInvalidKeyFormat() {
	err := ErrInvalidKeyFormat{Details: "bad key length"}
	s.Equal("invalid key format: bad key length", err.Error())
}

func (s *ErrorTypesSuite) TestErrOperationFailed() {
	originalErr := fmt.Errorf("underlying issue")
	err := ErrOperationFailed{Op: "test-op", Err: originalErr}
	s.Equal("crypto operation failed: test-op: underlying issue", err.Error())
	s.ErrorIs(err, originalErr)
	s.Equal(originalErr, err.Unwrap())
}

func TestErrorTypesSuite(t *testing.T) {
	suite.Run(t, new(ErrorTypesSuite))
}

// OptionsSuite groups options tests
type OptionsSuite struct {
	suite.Suite
}

func (s *OptionsSuite) TestRSAOptions() {
	cfg := &config{}
	kek := []byte("test-kek")
	hash := crypto.SHA512

	err := func(c *config) error { c.KEK = kek; return nil }(cfg)
	s.NoError(err)
	s.Equal(kek, cfg.KEK)

	err = WithHash(hash)(cfg)
	s.NoError(err)
	s.Equal(hash, cfg.Hash)
}

func (s *OptionsSuite) TestECOptions() {
	cfg := &config{}
	kek := []byte("test-kek-ec")
	ephemeral := []byte("test-ephemeral")

	err := func(c *config) error { c.KEK = kek; return nil }(cfg)
	s.NoError(err)
	s.Equal(kek, cfg.KEK)

	err = WithEphemeralKey(ephemeral)(cfg)
	s.NoError(err)
	s.Equal(ephemeral, cfg.EphemeralKey)
}

func TestOptionsSuite(t *testing.T) {
	suite.Run(t, new(OptionsSuite))
}
