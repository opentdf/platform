package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate a valid self-signed root certificate
func generateValidRootCert(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()

	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Encode to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM)
}

// Helper function to generate a non-CA certificate
func generateNonCACert(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Non-CA Cert",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false, // Not a CA certificate
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM)
}

// Helper function to generate a non-self-signed certificate
func generateNonSelfSignedCert(t *testing.T) string {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CA certificate
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CA Org"},
			CommonName:   "CA Root",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate leaf certificate key
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create leaf certificate with different subject (signed by CA)
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Leaf Org"},
			CommonName:   "Leaf Cert",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Sign leaf certificate with CA (not self-signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &caTemplate, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM)
}

// Helper function to generate a certificate with corrupted signature
func generateCertWithInvalidSignature(t *testing.T) string {
	t.Helper()

	// Start with a valid certificate
	validCert := generateValidRootCert(t, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))

	// Decode the PEM
	block, _ := pem.Decode([]byte(validCert))
	require.NotNil(t, block)

	// Corrupt the signature by modifying the last byte
	block.Bytes[len(block.Bytes)-1] ^= 0xFF

	// Re-encode to PEM
	corruptedPEM := pem.EncodeToMemory(block)
	return string(corruptedPEM)
}

func Test_validateRootCertificate(t *testing.T) {
	tests := []struct {
		name        string
		pemStr      string
		wantErr     bool
		errContains string
	}{
		{
			name:    "Valid root certificate",
			pemStr:  generateValidRootCert(t, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour)),
			wantErr: false,
		},
		{
			name:        "Missing BEGIN CERTIFICATE marker",
			pemStr:      "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----",
			wantErr:     true,
			errContains: "must contain BEGIN CERTIFICATE marker",
		},
		{
			name:        "Missing newlines",
			pemStr:      "-----BEGIN CERTIFICATE-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-----END CERTIFICATE-----",
			wantErr:     true,
			errContains: "must contain newlines",
		},
		{
			name:        "Invalid PEM format - failed decode",
			pemStr:      "-----BEGIN CERTIFICATE-----\ninvalid base64 content!!!\n-----END CERTIFICATE-----\n",
			wantErr:     true,
			errContains: "failed to decode PEM block",
		},
		{
			name: "Wrong PEM type - not CERTIFICATE",
			pemStr: `-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNV
BAcMBFRlc3QxDTALBgNVBAoMBFRlc3QxDTALBgNVBAsMBFRlc3QxDTALBgNVBAMM
BFRlc3QxGzAZBgkqhkiG9w0BCQEWDHRlc3RAdGVzdC5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCxkSWk
-----END CERTIFICATE REQUEST-----
`,
			wantErr:     true,
			errContains: "expected CERTIFICATE",
		},
		{
			name: "Invalid X.509 certificate",
			pemStr: `-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----
`,
			wantErr:     true,
			errContains: "not a valid X.509 certificate",
		},
		{
			name:        "Non-CA certificate (IsCA=false)",
			pemStr:      generateNonCACert(t),
			wantErr:     true,
			errContains: "must be a CA certificate",
		},
		{
			name:        "Non-self-signed certificate",
			pemStr:      generateNonSelfSignedCert(t),
			wantErr:     true,
			errContains: "must be a root certificate (self-signed)",
		},
		{
			name:        "Invalid signature",
			pemStr:      generateCertWithInvalidSignature(t),
			wantErr:     true,
			errContains: "signature verification failed",
		},
		{
			name:        "Certificate not yet valid (NotBefore in future)",
			pemStr:      generateValidRootCert(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)),
			wantErr:     true,
			errContains: "not yet valid",
		},
		{
			name:        "Expired certificate (NotAfter in past)",
			pemStr:      generateValidRootCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)),
			wantErr:     true,
			errContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRootCertificate(tt.pemStr)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
