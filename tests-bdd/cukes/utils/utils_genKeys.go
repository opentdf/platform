package utils //nolint:revive // test utility package

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path"
	"time"
)

const (
	rsaKeySize         = 2048
	serialNumberLenBit = 128
)

// GenerateTempKeys creates a set of RSA and EC certificates and cosign keys in the specified outputPath.
func GenerateTempKeys(outputPath string) {
	// Create directory if it doesn't exist
	err := os.MkdirAll(outputPath, 0o755)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	generateRSACertificate(outputPath)
	generateECParameters(outputPath)
	generateECCertificate(outputPath)
	generateJavaKeystore(outputPath)
}

// generateRSACertificate creates a self-signed RSA certificate and private key.
func generateRSACertificate(outputPath string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatalf("Failed to generate RSA private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), serialNumberLenBit)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kas",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create RSA certificate: %v", err)
	}

	certOut, err := os.Create(path.Join(outputPath, "kas-cert.pem"))
	if err != nil {
		log.Fatalf("Failed to open RSA certificate file for writing: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write RSA certificate to file: %v", err) //nolint:gocritic // test code
	}

	keyOut, err := os.Create(path.Join(outputPath, "kas-private.pem"))
	if err != nil {
		log.Fatalf("Failed to open RSA private key file for writing: %v", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write RSA private key to file: %v", err)
	}

	log.Println("RSA certificate and private key generated successfully:")
	log.Printf("  - Certificate: %s", path.Join(outputPath, "kas-cert.pem"))
	log.Printf("  - Private key: %s", path.Join(outputPath, "kas-private.pem"))
}

// generateECParameters creates a file with EC parameters for the prime256v1 curve.
func generateECParameters(outputPath string) {
	paramsOut, err := os.Create(path.Join(outputPath, "ecparams.tmp"))
	if err != nil {
		log.Fatalf("Failed to create EC parameters file: %v", err)
	}
	defer paramsOut.Close()

	ecParamBlock := &pem.Block{
		Type:  "EC PARAMETERS",
		Bytes: []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, // OID for prime256v1
	}

	if err := pem.Encode(paramsOut, ecParamBlock); err != nil {
		log.Fatalf("Failed to write EC parameters to file: %v", err) //nolint:gocritic // test code
	}

	log.Printf("EC parameters generated successfully: %s", path.Join(outputPath, "ecparams.tmp"))
}

// generateECCertificate creates a self-signed EC certificate and private key.
func generateECCertificate(outputPath string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate EC private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), serialNumberLenBit)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kas",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create EC certificate: %v", err)
	}

	certOut, err := os.Create(path.Join(outputPath, "kas-ec-cert.pem"))
	if err != nil {
		log.Fatalf("Failed to open EC certificate file for writing: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write EC certificate to file: %v", err) //nolint:gocritic // test code
	}

	keyOut, err := os.Create(path.Join(outputPath, "kas-ec-private.pem"))
	if err != nil {
		log.Fatalf("Failed to open EC private key file for writing: %v", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal EC private key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write EC private key to file: %v", err)
	}

	log.Println("EC certificate and private key generated successfully:")
	log.Printf("  - Certificate: %s", path.Join(outputPath, "kas-ec-cert.pem"))
	log.Printf("  - Private key: %s", path.Join(outputPath, "kas-ec-private.pem"))
}

// generateJavaKeystore creates a Java keystore (ca.jks) from the RSA certificate.
func generateJavaKeystore(outputPath string) {
	// Use keytool to create a Java keystore from the RSA certificate
	certPath := path.Join(outputPath, "kas-cert.pem")
	keystorePath := path.Join(outputPath, "ca.jks")

	// Create keystore using keytool command
	createJavaKeystore(certPath, keystorePath)
}

func createJavaKeystore(certPath, keystorePath string) {
	cmd := exec.Command("keytool", "-import", "-trustcacerts", "-noprompt", //nolint:noctx // test code
		"-alias", "ca",
		"-file", certPath,
		"-keystore", keystorePath,
		"-storepass", "password")

	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to create Java keystore (keytool required): %v", err)
	}

	log.Printf("Java keystore generated successfully: %s", keystorePath)
}
