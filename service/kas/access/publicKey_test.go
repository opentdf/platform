package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"testing"

	"connectrpc.com/connect"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

// MockKeyDetails is a test implementation of KeyDetails
type MockKeyDetails struct {
	id        trust.KeyIdentifier
	algorithm string
	legacy    bool
	certData  string
	pemData   string
	jwkData   string
}

func (m *MockKeyDetails) ID() trust.KeyIdentifier {
	return m.id
}

func (m *MockKeyDetails) Algorithm() string {
	return m.algorithm
}

func (m *MockKeyDetails) IsLegacy() bool {
	return m.legacy
}

func (m *MockKeyDetails) ExportPublicKey(_ context.Context, format trust.KeyType) (string, error) {
	switch format {
	case trust.KeyTypeJWK:
		if m.jwkData == "" {
			return "", errors.New("JWK data not available")
		}
		return m.jwkData, nil
	case trust.KeyTypePKCS8:
		if m.pemData == "" {
			return "", errors.New("PEM data not available")
		}
		return m.pemData, nil
	default:
		return "", errors.New("unsupported format")
	}
}

func (m *MockKeyDetails) ExportCertificate(_ context.Context) (string, error) {
	if m.certData == "" {
		return "", errors.New("certificate not available")
	}
	return m.certData, nil
}

// MockSecurityProvider is a test implementation of SecurityProvider
type MockSecurityProvider struct {
	keys map[trust.KeyIdentifier]*MockKeyDetails
}

func NewMockSecurityProvider() *MockSecurityProvider {
	return &MockSecurityProvider{
		keys: make(map[trust.KeyIdentifier]*MockKeyDetails),
	}
}

func (m *MockSecurityProvider) AddKey(key *MockKeyDetails) {
	m.keys[key.id] = key
}

func (m *MockSecurityProvider) FindKeyByAlgorithm(_ context.Context, algorithm string, includeLegacy bool) (trust.KeyDetails, error) {
	for _, key := range m.keys {
		if key.algorithm == algorithm && (!key.legacy || includeLegacy) {
			return key, nil
		}
	}
	return nil, security.ErrCertNotFound
}

func (m *MockSecurityProvider) FindKeyByID(_ context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	if key, ok := m.keys[id]; ok {
		return key, nil
	}
	return nil, security.ErrCertNotFound
}

func (m *MockSecurityProvider) ListKeys(_ context.Context) ([]trust.KeyDetails, error) {
	var keys []trust.KeyDetails
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *MockSecurityProvider) Decrypt(_ context.Context, _ trust.KeyIdentifier, _, _ []byte) (trust.ProtectedKey, error) {
	return nil, errors.New("not implemented for tests")
}

func (m *MockSecurityProvider) DeriveKey(_ context.Context, _ trust.KeyIdentifier, _ []byte, _ elliptic.Curve) (trust.ProtectedKey, error) {
	return nil, errors.New("not implemented for tests")
}

func (m *MockSecurityProvider) GenerateECSessionKey(_ context.Context, _ string) (trust.Encapsulator, error) {
	return nil, errors.New("not implemented for tests")
}

func (m *MockSecurityProvider) Close() {
	// Nothing to do
}

// Tests using the new SecurityProvider interface
func TestPublicKeyWithSecurityProvider(t *testing.T) {
	// Create mock security provider with test keys
	mockProvider := NewMockSecurityProvider()

	// Add RSA key
	mockProvider.AddKey(&MockKeyDetails{
		id:        "rsa-key",
		algorithm: security.AlgorithmRSA2048,
		legacy:    false,
		pemData:   "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\nkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\ncKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\nmwIDAQAB\n-----END PUBLIC KEY-----",
		jwkData:   "{\"kty\":\"RSA\",\"n\":\"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw\",\"e\":\"AQAB\"}",
	})

	// Add EC key
	mockProvider.AddKey(&MockKeyDetails{
		id:        "ec-key",
		algorithm: security.AlgorithmECP256R1,
		legacy:    false,
		pemData:   "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn6WYEj3sxP/IR0W1O5TYHKPyhceF\nki4Y/9YYeK/D3QkYQrv+DkKXPKkR/MQS6uzmHZY9NS8XbcwJ4cGpR6l4FQ==\n-----END PUBLIC KEY-----",
		certData:  "-----BEGIN CERTIFICATE-----\nMIIBcTCCARegAwIBAgIUTxgZ1CzWBXgysrV4bKVGw+1iBTwwCgYIKoZIzj0EAwIw\nDjEMMAoGA1UEAwwDa2FzMB4XDTIzMDYxMzAwMDAwMFoXDTI4MDYxMzAwMDAwMFow\nDjEMMAoGA1UEAwwDa2FzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn6WYEj3s\nxP/IR0W1O5TYHKPyhceFki4Y/9YYeK/D3QkYQrv+DkKXPKkR/MQS6uzmHZY9NS8X\nbcwJ4cGpR6l4FaNmMGQwHQYDVR0OBBYEFFQ8TIybvYhMKH0E+lOVDS0F7r9PMB8G\nA1UdIwQYMBaAFFQ8TIybvYhMKH0E+lOVDS0F7r9PMA8GA1UdEwEB/wQFMAMBAf8w\nEQYDVR0gBAowCDAGBgRVHSAAMAoGCCqGSM49BAMCA0gAMEUCIQD5adIeKGCpbI1E\nJr3jVwQNJL6+bLGXRORhIeKjpvd3egIgRZ7qwTpjZwrkXpDS2i1ODQjj2Ap9ZeMN\nzuDaXdOl90E=\n-----END CERTIFICATE-----",
	})

	kasURI := urlHost(t)

	// Create Provider with the mock security provider
	kas := Provider{
		URI:              *kasURI,
		SecurityProvider: mockProvider,
		KASConfig: KASConfig{
			Keyring: []CurrentKeyFor{
				{
					Algorithm: security.AlgorithmECP256R1,
					KID:       "ec-key",
				},
				{
					Algorithm: security.AlgorithmRSA2048,
					KID:       "rsa-key",
				},
			},
		},
		Logger: logger.CreateTestLogger(),
		Tracer: noop.NewTracerProvider().Tracer(""),
	}

	// Test PublicKey with RSA
	t.Run("PublicKey with RSA", func(t *testing.T) {
		result, err := kas.PublicKey(t.Context(), &connect.Request[kaspb.PublicKeyRequest]{
			Msg: &kaspb.PublicKeyRequest{
				Algorithm: security.AlgorithmRSA2048,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Msg.GetPublicKey(), "BEGIN PUBLIC KEY")
		assert.Equal(t, "rsa-key", result.Msg.GetKid())
	})

	// Test PublicKey with RSA in JWK format
	t.Run("PublicKey with RSA in JWK format", func(t *testing.T) {
		result, err := kas.PublicKey(t.Context(), &connect.Request[kaspb.PublicKeyRequest]{
			Msg: &kaspb.PublicKeyRequest{
				Algorithm: security.AlgorithmRSA2048,
				Fmt:       "jwk",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Msg.GetPublicKey(), "\"kty\":\"RSA\"")
		assert.Equal(t, "rsa-key", result.Msg.GetKid())
	})

	// Test PublicKey with EC
	t.Run("PublicKey with EC", func(t *testing.T) {
		result, err := kas.PublicKey(t.Context(), &connect.Request[kaspb.PublicKeyRequest]{
			Msg: &kaspb.PublicKeyRequest{
				Algorithm: security.AlgorithmECP256R1,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Msg.GetPublicKey(), "BEGIN PUBLIC KEY")
		assert.Equal(t, "ec-key", result.Msg.GetKid())
	})

	// Test LegacyPublicKey with EC
	t.Run("LegacyPublicKey with EC", func(t *testing.T) {
		result, err := kas.LegacyPublicKey(t.Context(), &connect.Request[kaspb.LegacyPublicKeyRequest]{
			Msg: &kaspb.LegacyPublicKeyRequest{
				Algorithm: security.AlgorithmECP256R1,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Msg.GetValue(), "BEGIN CERTIFICATE")
	})

	// Test LegacyPublicKey with RSA
	t.Run("LegacyPublicKey with RSA", func(t *testing.T) {
		result, err := kas.LegacyPublicKey(t.Context(), &connect.Request[kaspb.LegacyPublicKeyRequest]{
			Msg: &kaspb.LegacyPublicKeyRequest{
				Algorithm: security.AlgorithmRSA2048,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Msg.GetValue(), "BEGIN PUBLIC KEY")
	})

	// Test with invalid algorithm
	t.Run("PublicKey with invalid algorithm", func(t *testing.T) {
		result, err := kas.PublicKey(t.Context(), &connect.Request[kaspb.PublicKeyRequest]{
			Msg: &kaspb.PublicKeyRequest{
				Algorithm: "invalid-algorithm",
			},
		})
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})
}

func TestExportRsaPublicKeyAsPemStrSuccess(t *testing.T) {
	mockKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	output, err := exportRsaPublicKeyAsPemStr(mockKey)

	require.NoError(t, err)
	assert.NotEmpty(t, output)
	assert.IsType(t, "string", output)
}

func TestExportRsaPublicKeyAsPemStrFailure(t *testing.T) {
	output, err := exportRsaPublicKeyAsPemStr(&rsa.PublicKey{})
	assert.Empty(t, output)
	assert.Error(t, err)
}

func TestExportEcPublicKeyAsPemStrSuccess(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	output, err := exportEcPublicKeyAsPemStr(&privateKey.PublicKey)
	require.NoError(t, err)

	assert.NotEmpty(t, output)
	assert.IsType(t, "string", output)
}

func TestExportEcPublicKeyAsPemStrFailure(t *testing.T) {
	output, err := exportEcPublicKeyAsPemStr(&ecdsa.PublicKey{})
	assert.Empty(t, output)
	assert.Error(t, err)
}

func TestExportCertificateAsPemStrSuccess(t *testing.T) {
	certBytes, err := os.ReadFile("./testdata/cert.der")
	require.NoError(t, err, "Failed to read certificate file in test")

	mockCert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err, "Failed to parse certificate in test")

	pemStr, err := exportCertificateAsPemStr(mockCert)
	require.NoError(t, err)

	// Decode the pemStr back into a block
	pemBlock, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, pemBlock)

	// Ensure that the PEM block has the expected type "CERTIFICATE"
	assert.Equal(t, "CERTIFICATE", pemBlock.Type)

	// Compare the decoded certificate bytes with the original mock certificate bytes
	assert.Equal(t, certBytes, pemBlock.Bytes)
}

func TestError(t *testing.T) {
	output := Error.Error(ErrCertificateEncode)
	assert.Equal(t, "certificate encode error", output)
}

const hostname = "localhost"

func TestStandardCertificateHandlerEmpty(t *testing.T) {
	configStandard := security.Config{
		Type: "standard",
	}
	c := mustNewCryptoProvider(t, configStandard)
	defer c.Close()
	kasURI := urlHost(t)

	kas := Provider{
		URI:              *kasURI,
		SecurityProvider: security.NewSecurityProviderAdapter(c),
		Logger:           logger.CreateTestLogger(),
		Tracer:           noop.NewTracerProvider().Tracer(""),
	}

	result, err := kas.PublicKey(t.Context(), &connect.Request[kaspb.PublicKeyRequest]{Msg: &kaspb.PublicKeyRequest{Fmt: "pkcs8"}})
	require.Error(t, err, "not found")
	assert.Nil(t, result)
}

func mustNewCryptoProvider(t *testing.T, configStandard security.Config) security.CryptoProvider {
	c, err := security.NewCryptoProvider(configStandard)
	require.NoError(t, err)
	require.NotNil(t, c)
	return c
}

func urlHost(t *testing.T) *url.URL {
	url, err := url.Parse("https://" + hostname + ":5000")
	require.NoError(t, err)
	return url
}

// Original tests kept for backward compatibility
// They test the direct CryptoProvider usage path
