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
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != RSA2048Key || info.RSABits != RSA2048Size {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidatePublicKeyPEM_RSA4096(t *testing.T) {
	pem := mustRead(t, "testdata/sample-rsa-4096-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != RSA4096Key || info.RSABits != RSA4096Size {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidatePublicKeyPEM_RSA1024_Invalid(t *testing.T) {
	pem := mustRead(t, "testdata/sample-rsa-1024-01-public.pem")
	if _, err := ValidatePublicKeyPEM(pem); !errors.Is(err, ErrInvalidRSAKeySize) {
		t.Fatalf("expected ErrInvalidRSAKeySize, got %v", err)
	}
}

func TestValidatePublicKeyPEM_EC256(t *testing.T) {
	pem := mustRead(t, "testdata/sample-ec-secp256r1-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != EC256Key || info.ECCurve != ECCModeSecp256r1 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidatePublicKeyPEM_EC384(t *testing.T) {
	pem := mustRead(t, "testdata/sample-ec-secp384r1-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != EC384Key || info.ECCurve != ECCModeSecp384r1 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidatePublicKeyPEM_EC521(t *testing.T) {
	pem := mustRead(t, "testdata/sample-ec-secp521r1-01-public.pem")
	info, err := ValidatePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != EC521Key || info.ECCurve != ECCModeSecp521r1 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidatePublicKeyPEM_InvalidPEMBlock(t *testing.T) {
	// use a PRIVATE KEY pem to ensure the block type check fails
	pem := mustRead(t, "testdata/sample-rsa-2048-01-private.pem")
	if _, err := ValidatePublicKeyPEM(pem); !errors.Is(err, ErrInvalidPEMBlock) {
		t.Fatalf("expected ErrInvalidPEMBlock, got %v", err)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != RSA2048Key || info.Source != SourceCertificate {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidateCertificatePEM_EC521(t *testing.T) {
	certPEM := genSelfSignedECCert(t, elliptic.P521())
	info, err := ValidatePublicKeyPEM(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != EC521Key || info.ECCurve != ECCModeSecp521r1 || info.Source != SourceCertificate {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestValidateMultiPEM_ValidPublicKeyThenInvalidCertificate_ShouldError(t *testing.T) {
	// Start with a valid RSA 2048 public key
	pub := mustRead(t, "testdata/sample-rsa-2048-01-public.pem")
	// Append an invalid CERTIFICATE block (invalid DER contents)
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")})
	combo := append(append([]byte{}, pub...), badCert...)

	if _, err := ValidatePublicKeyPEM(combo); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("expected ErrInvalidPublicKey for corrupted certificate, got %v", err)
	}
}

func TestValidateMultiPEM_ValidCertificateThenValidPublicKey_FirstValidReturned(t *testing.T) {
	cert := genSelfSignedECCert(t, elliptic.P256())
	pub := mustRead(t, "testdata/sample-rsa-2048-01-public.pem")
	combo := append(append([]byte{}, cert...), pub...)

	info, err := ValidatePublicKeyPEM(combo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Source != SourceCertificate {
		t.Fatalf("expected first valid source to be certificate, got: %+v", info)
	}
}

func TestValidateMultiPEM_OnlyPrivateKey_ShouldErrInvalidPEMBlock(t *testing.T) {
	pk := mustRead(t, "testdata/sample-rsa-2048-01-private.pem")
	if _, err := ValidatePublicKeyPEM(pk); !errors.Is(err, ErrInvalidPEMBlock) {
		t.Fatalf("expected ErrInvalidPEMBlock for unsupported-only blocks, got %v", err)
	}
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

	if _, err := ValidatePublicKeyPEM(certPEM); !errors.Is(err, ErrUnsupportedPublicKeyType) {
		t.Fatalf("expected ErrUnsupportedPublicKeyType for ed25519, got %v", err)
	}
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

	if _, err := ValidatePublicKeyPEM(certPEM); !errors.Is(err, ErrInvalidECCurve) {
		t.Fatalf("expected ErrInvalidECCurve for P-224, got %v", err)
	}
}
