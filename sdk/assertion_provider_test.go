package sdk

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultSigningProvider tests the default key-based signing provider
func TestDefaultSigningProvider(t *testing.T) {
	// Create a test key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privKey,
	}

	provider := NewDefaultSigningProvider(key)

	// Create a test assertion
	assertion := &Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "json",
			Schema: "test-schema",
			Value:  `{"test": "value"}`,
		},
	}

	// Sign the assertion
	signature, err := provider.Sign(context.Background(), assertion, "test-hash", "test-sig")
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify the signature format (should be JWS compact)
	parts := splitCompact(signature)
	assert.Len(t, parts, 3)

	// Verify we can parse it as JWT
	tok, err := jwt.Parse([]byte(signature), jwt.WithKey(jwa.RS256, &privKey.PublicKey))
	require.NoError(t, err)

	// Check claims
	hashClaim, ok := tok.Get(kAssertionHash)
	assert.True(t, ok)
	assert.Equal(t, "test-hash", hashClaim)

	sigClaim, ok := tok.Get(kAssertionSignature)
	assert.True(t, ok)
	assert.Equal(t, "test-sig", sigClaim)

	// Test provider metadata
	assert.Equal(t, "RS256", provider.GetAlgorithm())
	assert.Equal(t, "key-alg:RS256", provider.GetSigningKeyReference())
}

// TestDefaultValidationProvider tests the default key-based validation provider
func TestDefaultValidationProvider(t *testing.T) {
	// Create a test key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signingKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privKey,
	}

	// Create and sign assertion
	assertion := Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
	}

	err = assertion.Sign("test-hash", "test-sig", signingKey)
	require.NoError(t, err)

	// Create validation provider with public key
	validationKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: &privKey.PublicKey,
	}

	provider := NewDefaultValidationProviderWithKey(validationKey)

	// Validate the assertion
	hash, sig, err := provider.Validate(context.Background(), assertion)
	require.NoError(t, err)
	assert.Equal(t, "test-hash", hash)
	assert.Equal(t, "test-sig", sig)

	// Test trust check
	err = provider.IsTrusted(context.Background(), assertion)
	assert.NoError(t, err)

	// Test authorities
	authorities := provider.GetTrustedAuthorities()
	assert.Contains(t, authorities, "default:RS256")
}

// TestX509SigningProvider tests certificate-based signing
func TestX509SigningProvider(t *testing.T) {
	// Generate test certificate and key
	privKey, cert := generateTestCertificate(t)

	provider, err := NewX509SigningProvider(privKey, []*x509.Certificate{cert})
	require.NoError(t, err)

	// Create a test assertion
	assertion := &Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
	}

	// Sign the assertion
	signature, err := provider.Sign(context.Background(), assertion, "test-hash", "test-sig")
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// The actual x5c header would be added by hardware/PKCS#11 implementation
	// For this test, we just verify the signature was created
	msg, err := jws.Parse([]byte(signature))
	require.NoError(t, err)

	signatures := msg.Signatures()
	require.Len(t, signatures, 1)

	// Test provider metadata
	assert.Equal(t, "RS256", provider.GetAlgorithm())
	assert.Equal(t, cert.Subject.String(), provider.GetSigningKeyReference())
}

// TestX509ValidationProvider tests certificate-based validation
func TestX509ValidationProvider(t *testing.T) {
	// For this test, we'll simulate the validation flow
	// In real usage, the x5c would be embedded by hardware tokens

	// Generate test certificate and key
	privKey, cert := generateTestCertificate(t)

	// Create a standard signing (without x5c for now)
	key := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privKey,
	}

	// Create and sign assertion with standard method
	assertion := Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
	}

	err := assertion.Sign("test-hash", "test-sig", key)
	require.NoError(t, err)

	// Create validation provider with trust settings
	trustPool := x509.NewCertPool()
	trustPool.AddCert(cert)

	// For now, test the validation provider setup and trust checking
	validationProvider := NewX509ValidationProvider(X509ValidationOptions{
		TrustedCAs:             trustPool,
		AllowSelfSigned:        true,
		RequireChainValidation: false,
	})

	// Test authorities (the main validation would work with real x5c headers)
	authorities := validationProvider.GetTrustedAuthorities()
	assert.Contains(t, authorities, "self-signed-allowed")

	// Test that the provider is properly configured
	assert.NotNil(t, validationProvider.options.TrustedCAs)
	assert.True(t, validationProvider.options.AllowSelfSigned)
}

// TestPayloadKeyProvider tests HMAC-based signing with payload key
func TestPayloadKeyProvider(t *testing.T) {
	payloadKey := []byte("test-payload-key-32-bytes-long!!")

	provider := NewPayloadKeyProvider(payloadKey)

	// Create a test assertion
	assertion := &Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
	}

	// Sign the assertion
	signature, err := provider.Sign(context.Background(), assertion, "test-hash", "test-sig")
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify with validation provider
	validationProvider := NewPayloadKeyValidationProvider(payloadKey)

	assertion.Binding = Binding{
		Method:    "jws",
		Signature: signature,
	}

	hash, sig, err := validationProvider.Validate(context.Background(), *assertion)
	require.NoError(t, err)
	assert.Equal(t, "test-hash", hash)
	assert.Equal(t, "test-sig", sig)

	// Test provider metadata
	assert.Equal(t, "HS256", provider.GetAlgorithm())
	assert.Equal(t, "payload-key:HS256", provider.GetSigningKeyReference())
}

// TestProviderErrors tests error conditions
func TestProviderErrors(t *testing.T) {
	t.Run("EmptyKeyError", func(t *testing.T) {
		provider := NewDefaultSigningProvider(AssertionKey{})
		_, err := provider.Sign(context.Background(), &Assertion{}, "hash", "sig")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signing key not configured")
	})

	t.Run("InvalidSignatureError", func(t *testing.T) {
		key := AssertionKey{
			Alg: AssertionKeyAlgHS256,
			Key: []byte("test-key"),
		}
		provider := NewDefaultValidationProviderWithKey(key)

		assertion := Assertion{
			Binding: Binding{
				Method:    "jws",
				Signature: "invalid.signature.here",
			},
		}

		_, _, err := provider.Validate(context.Background(), assertion)
		assert.Error(t, err)
	})

	t.Run("MissingX5CError", func(t *testing.T) {
		provider := NewX509ValidationProvider(X509ValidationOptions{})

		// Create assertion without x5c
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		tok := jwt.New()
		_ = tok.Set(kAssertionHash, "hash")
		_ = tok.Set(kAssertionSignature, "sig")

		signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
		require.NoError(t, err)

		assertion := Assertion{
			Binding: Binding{
				Method:    "jws",
				Signature: string(signedTok),
			},
		}

		_, _, err = provider.Validate(context.Background(), assertion)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "x5c header not found")
	})
}

// TestCustomProvider tests implementing a custom provider
func TestCustomProvider(t *testing.T) {
	// Create a mock custom provider
	customProvider := &mockSigningProvider{
		signFunc: func(ctx context.Context, assertion *Assertion, hash, sig string) (string, error) {
			// Custom logic here
			return "custom-signature", nil
		},
		keyRef: "custom-key-ref",
		alg:    "CUSTOM",
	}

	signature, err := customProvider.Sign(context.Background(), &Assertion{}, "hash", "sig")
	require.NoError(t, err)
	assert.Equal(t, "custom-signature", signature)
	assert.Equal(t, "custom-key-ref", customProvider.GetSigningKeyReference())
	assert.Equal(t, "CUSTOM", customProvider.GetAlgorithm())
}

// Helper functions

func generateTestCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return privKey, cert
}

func splitCompact(compact string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i, r := range compact {
		if r == '.' {
			parts = append(parts, compact[start:i])
			start = i + 1
		}
	}
	parts = append(parts, compact[start:])
	return parts
}

// Mock provider for testing custom implementations

type mockSigningProvider struct {
	signFunc func(context.Context, *Assertion, string, string) (string, error)
	keyRef   string
	alg      string
}

func (m *mockSigningProvider) Sign(ctx context.Context, assertion *Assertion, hash, sig string) (string, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, assertion, hash, sig)
	}
	return "", errors.New("not implemented")
}

func (m *mockSigningProvider) GetSigningKeyReference() string {
	return m.keyRef
}

func (m *mockSigningProvider) GetAlgorithm() string {
	return m.alg
}

// Mock validation provider

type mockValidationProvider struct {
	validateFunc func(context.Context, Assertion) (string, string, error)
	trustFunc    func(context.Context, Assertion) error
	authorities  []string
}

func (m *mockValidationProvider) Validate(ctx context.Context, assertion Assertion) (string, string, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, assertion)
	}
	return "", "", errors.New("not implemented")
}

func (m *mockValidationProvider) IsTrusted(ctx context.Context, assertion Assertion) error {
	if m.trustFunc != nil {
		return m.trustFunc(ctx, assertion)
	}
	return nil
}

func (m *mockValidationProvider) GetTrustedAuthorities() []string {
	return m.authorities
}
