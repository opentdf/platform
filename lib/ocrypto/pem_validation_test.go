package ocrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return b
}

func TestValidatePublicKeyPEM_RSA2048(t *testing.T) {
	pem := mustRead(t, "testdata/sample-rsa-2048-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	require.NoError(t, err)
	assert.Equal(t, RSA2048Key, info.Type)
	assert.Equal(t, RSA2048Size, info.RSABits)
	assert.Equal(t, 0, int(info.ECCurve))
}

func TestValidatePublicKeyPEM_RSA4096(t *testing.T) {
	pem := mustRead(t, "testdata/sample-rsa-4096-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	require.NoError(t, err)
	assert.Equal(t, RSA4096Key, info.Type)
	assert.Equal(t, RSA4096Size, info.RSABits)
	assert.Equal(t, 0, int(info.ECCurve))
}

func TestValidatePublicKeyPEM_RSA1024_Invalid(t *testing.T) {
	pem := mustRead(t, "testdata/sample-rsa-1024-01-public.pem")
	_, err := ValidatePublicKeyPEM(pem)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidRSAKeySize)
}

func TestValidatePublicKeyPEM_EC256(t *testing.T) {
	pem := mustRead(t, "testdata/sample-ec-secp256r1-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	require.NoError(t, err)
	assert.Equal(t, EC256Key, info.Type)
	assert.Equal(t, ECCModeSecp256r1, info.ECCurve)
}

func TestValidatePublicKeyPEM_EC384(t *testing.T) {
	pem := mustRead(t, "testdata/sample-ec-secp384r1-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	require.NoError(t, err)
	assert.Equal(t, EC384Key, info.Type)
	assert.Equal(t, ECCModeSecp384r1, info.ECCurve)
}

func TestValidatePublicKeyPEM_EC521(t *testing.T) {
	pem := mustRead(t, "testdata/sample-ec-secp521r1-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	require.NoError(t, err)
	assert.Equal(t, EC521Key, info.Type)
	assert.Equal(t, ECCModeSecp521r1, info.ECCurve)
}

func TestValidatePublicKeyPEM_InvalidPEMBlock(t *testing.T) {
	// use a PRIVATE KEY pem to ensure the block type check fails
	pem := mustRead(t, "testdata/sample-rsa-2048-01-private.pem")
	_, err := ValidatePublicKeyPEM(pem)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPEMBlock)
}

// Helpers to generate quick self-signed certificates for certificate parsing path
func genSelfSignedRSACert(t *testing.T, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func genSelfSignedECCert(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-ec"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestValidateCertificatePEM_RSA2048(t *testing.T) {
	certPEM := genSelfSignedRSACert(t, 2048)
	info, err := ValidatePublicKeyPEM(certPEM)
	require.NoError(t, err)
	assert.Equal(t, RSA2048Key, info.Type)
	assert.Equal(t, KeySourceCertificate, info.Source)
}

func TestValidateCertificatePEM_EC521(t *testing.T) {
	certPEM := genSelfSignedECCert(t, elliptic.P521())
	info, err := ValidatePublicKeyPEM(certPEM)
	require.NoError(t, err)
	assert.Equal(t, EC521Key, info.Type)
	assert.Equal(t, ECCModeSecp521r1, info.ECCurve)
	assert.Equal(t, KeySourceCertificate, info.Source)
}

func TestValidateMultiPEM_ValidPublicKeyThenInvalidCertificate_ShouldError(t *testing.T) {
	// Start with a valid RSA 2048 public key
	pub := mustRead(t, "testdata/sample-rsa-2048-01-public.pem")
	// Append an invalid CERTIFICATE block (invalid DER contents)
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")})
	combo := append(append([]byte{}, pub...), badCert...)

	_, err := ValidatePublicKeyPEM(combo)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestValidateMultiPEM_ValidCertificateThenValidPublicKey_FirstValidReturned(t *testing.T) {
	cert := genSelfSignedECCert(t, elliptic.P256())
	pub := mustRead(t, "testdata/sample-rsa-2048-01-public.pem")
	combo := append(append([]byte{}, cert...), pub...)

	info, err := ValidatePublicKeyPEM(combo)
	require.NoError(t, err)
	assert.Equal(t, KeySourceCertificate, info.Source)
}

func TestValidateMultiPEM_OnlyPrivateKey_ShouldErrInvalidPEMBlock(t *testing.T) {
	pk := mustRead(t, "testdata/sample-rsa-2048-01-private.pem")
	_, err := ValidatePublicKeyPEM(pk)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPEMBlock)
}

// Additional negative tests requested by review
func TestValidateCertificatePEM_UnsupportedKeyType_Ed25519(t *testing.T) {
	// Generate Ed25519 self-signed cert
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "test-ed25519"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	_, err = ValidatePublicKeyPEM(certPEM)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedPublicKeyType)
}

func TestValidateCertificatePEM_UnsupportedECCurve_P224(t *testing.T) {
	// Generate P-224 self-signed cert (unsupported curve)
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P224): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "test-p224"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	_, err = ValidatePublicKeyPEM(certPEM)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidECCurve)
}

func TestValidateMultiPEM_UnrelatedBlockThenValidPublicKey_Succeeds(t *testing.T) {
	// Create an unrelated block followed by a valid RSA 2048 public key
	unrelated := pem.EncodeToMemory(&pem.Block{Type: "UNRELATED", Bytes: []byte("noise")})
	pub := mustRead(t, "testdata/sample-rsa-2048-01-public.pem")
	combo := append(append([]byte{}, unrelated...), pub...)

	info, err := ValidatePublicKeyPEM(combo)
	require.NoError(t, err)
	assert.Equal(t, RSA2048Key, info.Type)
	assert.Equal(t, KeySourcePublicKey, info.Source)
}

func TestValidateCorruptedPublicKeyPEM_Invalid(t *testing.T) {
	// Create a PUBLIC KEY block with malformed DER
	badPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not-a-der-public-key")})
	_, err := ValidatePublicKeyPEM(badPub)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestValidateCorruptedCertificatePEM_Invalid(t *testing.T) {
	// Create a CERTIFICATE block with malformed DER
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-der-cert")})
	_, err := ValidatePublicKeyPEM(badCert)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}
