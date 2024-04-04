package access

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/opentdf/platform/service/internal/security"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/stretchr/testify/assert"
)

func TestExportRsaPublicKeyAsPemStrSuccess(t *testing.T) {
	mockKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	output, err := exportRsaPublicKeyAsPemStr(mockKey)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if len(output) == 0 {
		t.Error("Expected not empty string")
	}

	if reflect.TypeOf(output).String() != "string" {
		t.Errorf("Output %v not equal to expected %v", reflect.TypeOf(output).String(), "string")
	}
}

func TestExportRsaPublicKeyAsPemStrFailure(t *testing.T) {
	output, err := exportRsaPublicKeyAsPemStr(&rsa.PublicKey{})

	if output != "" {
		t.Errorf("Expected empty string, but got: %v", output)
	}

	if err == nil {
		t.Errorf("Expected error, but got: %v", err)
	}
}

func TestExportEcPublicKeyAsPemStrSuccess(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}
	output, err := exportEcPublicKeyAsPemStr(&privateKey.PublicKey)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if len(output) == 0 {
		t.Error("Expected not empty string")
	}

	if reflect.TypeOf(output).String() != "string" {
		t.Errorf("Output %v not equal to expected %v", reflect.TypeOf(output).String(), "string")
	}
}

func TestExportEcPublicKeyAsPemStrFailure(t *testing.T) {
	output, err := exportEcPublicKeyAsPemStr(&ecdsa.PublicKey{})

	if output != "" {
		t.Errorf("Expected empty string, but got: %v", output)
	}

	if err == nil {
		t.Errorf("Expected error, but got: %v", err)
	}
}

func TestExportCertificateAsPemStrSuccess(t *testing.T) {
	certBytes, err := os.ReadFile("./testdata/cert.der")
	if err != nil {
		t.Errorf("Failed to read certificate file in test: %v", err)
	}

	mockCert, err := x509.ParseCertificate(certBytes)
	assert.NoError(t, err, "Failed to parse certificate in test")

	pemStr, err := exportCertificateAsPemStr(mockCert)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	// Decode the pemStr back into a block
	pemBlock, _ := pem.Decode([]byte(pemStr))
	if pemBlock == nil {
		t.Fatal("Failed to decode PEM block from the generated string")
	}

	// Ensure that the PEM block has the expected type "CERTIFICATE"
	if pemBlock.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM block type to be 'CERTIFICATE', but got '%s'", pemBlock.Type)
	}

	// Compare the decoded certificate bytes with the original mock certificate bytes
	if !bytes.Equal(pemBlock.Bytes, certBytes) {
		t.Error("Certificate bytes mismatch")
	}
}

func TestError(t *testing.T) {
	expectedResult := "certificate encode error"
	output := Error.Error(ErrCertificateEncode)

	if reflect.TypeOf(output).String() != "string" {
		t.Error("Expected string")
	}

	if output != expectedResult {
		t.Errorf("Output %v not equal to expected %v", output, expectedResult)
	}
}

const hostname = "localhost"

func TestCertificateHandlerEmpty(t *testing.T) {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Fmt: "pkcs8"})
	assert.Error(t, err, "not found")
	assert.Nil(t, result)
}

func TestCertificateHandlerWithEc256(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}
	kas.Session.EC = &security.ECKeyPair{
		PublicKey:   &privateKey.PublicKey,
		Certificate: &x509.Certificate{},
	}

	result, err := kas.LegacyPublicKey(context.Background(), &kaspb.LegacyPublicKeyRequest{Algorithm: "ec:secp256r1"})
	if err != nil {
		t.Errorf("got %s, but should be nil", err)
	}
	if result == nil || !strings.Contains(result.GetValue(), "BEGIN CERTIFICATE") {
		t.Errorf("got %s, but should be cert", result)
	}
}

func TestPublicKeyHandlerWithEc256(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}
	kas.Session.EC = &security.ECKeyPair{
		PublicKey: &privateKey.PublicKey,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "ec:secp256r1"})
	if err != nil {
		t.Errorf("got %s, but should be nil", err)
	}
	if result == nil || !strings.Contains(result.GetPublicKey(), "BEGIN PUBLIC KEY") {
		t.Errorf("got %s, but should be public key", result)
	}
}

func TestPublicKeyHandlerV2(t *testing.T) {
	mockPublicKeyRsa := rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}
	kas.Session.EC = &security.ECKeyPair{
		PublicKey: &privateKey.PublicKey,
	}
	kas.Session.RSA = &security.RSAKeyPair{
		Certificate: &x509.Certificate{},
		PublicKey:   &mockPublicKeyRsa,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "rsa"})
	if err != nil {
		t.Errorf("got %s, but should be nil", err)
	}
	if !strings.Contains(result.GetPublicKey(), "BEGIN PUBLIC KEY") {
		t.Errorf("got %s, but should be pubkey", result)
	}
}

func TestPublicKeyHandlerV2Failure(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}
	kas.Session.EC = &security.ECKeyPair{
		PublicKey: &privateKey.PublicKey,
	}

	_, err = kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "rsa"})
	if err == nil {
		t.Errorf("got nil error")
	}
}

func TestPublicKeyHandlerV2WithEc256(t *testing.T) {
	mockPublicKeyRsa := rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}
	kas.Session.EC = &security.ECKeyPair{
		PublicKey: &privateKey.PublicKey,
	}
	kas.Session.RSA = &security.RSAKeyPair{
		Certificate: &x509.Certificate{},
		PublicKey:   &mockPublicKeyRsa,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{Algorithm: "ec:secp256r1",
		V: "2"})
	if err != nil {
		t.Errorf("got %s, but should be nil", err)
	}
	if !strings.Contains(result.GetPublicKey(), "BEGIN PUBLIC KEY") {
		t.Errorf("got %s, but should be pubkey", result)
	}
}

func TestPublicKeyHandlerV2WithJwk(t *testing.T) {
	mockPublicKeyRsa := rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		Session:      security.HSMSession{},
		OIDCVerifier: nil,
	}
	kas.Session.EC = &security.ECKeyPair{
		PublicKey: &privateKey.PublicKey,
	}
	kas.Session.RSA = &security.RSAKeyPair{
		Certificate: &x509.Certificate{},
		PublicKey:   &mockPublicKeyRsa,
	}

	result, err := kas.PublicKey(context.Background(), &kaspb.PublicKeyRequest{
		Algorithm: "rsa",
		V:         "2",
		Fmt:       "jwk",
	})
	if err != nil {
		t.Errorf("got %s, but should be nil", err)
	}
	if !strings.Contains(result.GetPublicKey(), "\"kty\"") {
		t.Errorf("got %s, but should be JSON Web Key", result.GetPublicKey())
	}
}
