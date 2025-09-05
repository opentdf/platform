package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificateForX5C creates a self-signed certificate for testing x5c functionality
func generateTestCertificateForX5C(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org X5C"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "X5C Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return priv, cert
}

func TestX509SigningProviderWithX5C(t *testing.T) {
	// Generate test certificate
	privKey, cert := generateTestCertificateForX5C(t)

	// Create signing provider
	provider, err := NewX509SigningProvider(privKey, []*x509.Certificate{cert})
	require.NoError(t, err)
	assert.Equal(t, "RS256", provider.GetAlgorithm())
	assert.Contains(t, provider.GetSigningKeyReference(), "Test Org")

	// Create assertion
	assertion := &Assertion{
		ID:    "test-assertion",
		Type:  HandlingAssertion,
		Scope: TrustedDataObjScope,
		Statement: Statement{
			Format: "plain",
			Value:  "test statement",
		},
	}

	// Sign the assertion
	ctx := t.Context()
	signature, err := provider.Sign(ctx, assertion, "testhash123", "testsig456")
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Verify the signature has x5c header
	parts := strings.Split(signature, ".")
	require.Len(t, parts, 3, "JWS should have 3 parts")

	// Decode and check header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]interface{}
	err = json.Unmarshal(headerJSON, &header)
	require.NoError(t, err)

	// Check x5c is present
	x5c, ok := header["x5c"]
	require.True(t, ok, "x5c header should be present")

	x5cArray, ok := x5c.([]interface{})
	require.True(t, ok, "x5c should be an array")
	require.Len(t, x5cArray, 1, "x5c should contain one certificate")

	// Verify the certificate in x5c matches our test cert
	certB64, ok := x5cArray[0].(string)
	require.True(t, ok, "x5c certificate should be a string")

	certDER, err := base64.StdEncoding.DecodeString(certB64)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, cert.Subject.String(), parsedCert.Subject.String())

	// Verify the signature with the public key
	_, err = jws.Verify([]byte(signature), jws.WithKey(jwa.RS256, cert.PublicKey))
	require.NoError(t, err)

	// Parse as JWT and check claims
	tok, err := jwt.Parse([]byte(signature), jwt.WithKey(jwa.RS256, cert.PublicKey))
	require.NoError(t, err)

	hashClaim, ok := tok.Get(kAssertionHash)
	require.True(t, ok)
	assert.Equal(t, "testhash123", hashClaim)

	sigClaim, ok := tok.Get(kAssertionSignature)
	require.True(t, ok)
	assert.Equal(t, "testsig456", sigClaim)
}

func TestX509ValidationProviderWithX5C(t *testing.T) {
	// Generate test certificate
	privKey, cert := generateTestCertificateForX5C(t)

	// Create signing provider to generate proper JWS with x5c
	signingProvider, err := NewX509SigningProvider(privKey, []*x509.Certificate{cert})
	require.NoError(t, err)

	// Use the provider to create a signed assertion
	ctx := t.Context()
	signedTok, err := signingProvider.Sign(ctx, &Assertion{}, "testhash789", "testsig012")
	require.NoError(t, err)

	// Create assertion with the signature
	assertion := Assertion{
		Binding: Binding{
			Method:    "jws",
			Signature: signedTok,
		},
	}

	// Create validation provider with the certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	validationProvider := NewX509ValidationProvider(X509ValidationOptions{
		TrustedCAs:      certPool,
		AllowSelfSigned: true,
	})

	// Validate the assertion
	hash, sig, err := validationProvider.Validate(t.Context(), assertion)
	require.NoError(t, err)
	assert.Equal(t, "testhash789", hash)
	assert.Equal(t, "testsig012", sig)

	// Check trusted authorities
	authorities := validationProvider.GetTrustedAuthorities()
	assert.Contains(t, authorities, "configured-trusted-cas")
	assert.Contains(t, authorities, "self-signed-allowed")
}

func TestX509ValidationProviderWithCerts(t *testing.T) {
	// Generate multiple test certificates
	_, cert1 := generateTestCertificateForX5C(t)
	_, cert2 := generateTestCertificateForX5C(t)

	// Create validation provider with certificates
	validationProvider := NewX509ValidationProviderWithCerts(
		[]*x509.Certificate{cert1, cert2},
		X509ValidationOptions{
			RequiredPolicies: []string{"2.16.840.1.101.3.2.1.3.13"},
		},
	)

	// Check that certificates were added to trusted authorities
	authorities := validationProvider.GetTrustedAuthorities()
	assert.Len(t, authorities, 3) // 2 certs + 1 policy
	assert.Contains(t, authorities, cert1.Subject.String())
	assert.Contains(t, authorities, cert2.Subject.String())
	assert.Contains(t, authorities, "policy:2.16.840.1.101.3.2.1.3.13")
}

func TestExtractX5CCertificates(t *testing.T) {
	// Generate test certificate
	privKey, cert := generateTestCertificateForX5C(t)

	// Create signing provider to generate proper JWS with x5c
	signingProvider, err := NewX509SigningProvider(privKey, []*x509.Certificate{cert})
	require.NoError(t, err)

	// Use the provider to create a signed assertion with x5c
	ctx := t.Context()
	signedTok, err := signingProvider.Sign(ctx, &Assertion{}, "test", "value")
	require.NoError(t, err)

	// Extract certificates
	certs, err := ExtractX5CCertificates(signedTok)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, cert.Subject.String(), certs[0].Subject.String())
}

func TestPKCS11ProviderStub(t *testing.T) {
	// Test PKCS11 provider creation
	config := HardwareSigningOptions{
		SlotID:           "0",
		PIN:              []byte("123456"),
		KeyLabel:         "Test Key",
		Algorithm:        "RS256",
		IncludeCertChain: true,
	}

	provider, err := NewPKCS11Provider(config)
	require.NoError(t, err)
	assert.Equal(t, "RS256", provider.GetAlgorithm())
	assert.Contains(t, provider.GetSigningKeyReference(), "pkcs11:slot=0")

	// Test that signing returns not implemented error (since we don't have real hardware)
	ctx := t.Context()
	assertion := &Assertion{}
	_, err = provider.Sign(ctx, assertion, "hash", "sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestPIVProvider(t *testing.T) {
	provider, err := NewPIVProvider([]byte("123456"), "9a")
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "RS256", provider.GetAlgorithm())
}

func TestCACProvider(t *testing.T) {
	provider, err := NewCACProvider([]byte("123456"), "01")
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "RS256", provider.GetAlgorithm())
}
