package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// jwkToPEMForTest converts a jwk.Key to PEM for round-trip testing.
func jwkToPEMForTest(t *testing.T, key interface{ Raw(any) error }) []byte {
	t.Helper()
	var raw any
	if err := key.Raw(&raw); err != nil {
		t.Fatalf("failed to get raw key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(raw)
	if err != nil {
		t.Fatalf("failed to marshal key to PKCS8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestGenerateDPoPKeyForAlg_EC(t *testing.T) {
	tests := []struct {
		alg     string
		wantAlg jwa.SignatureAlgorithm
		curve   elliptic.Curve
	}{
		{dpopAlgES256, jwa.ES256, elliptic.P256()},
		{dpopAlgES384, jwa.ES384, elliptic.P384()},
		{dpopAlgES512, jwa.ES512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			key, err := generateDPoPKeyForAlg(tt.alg)
			if err != nil {
				t.Fatalf("generateDPoPKeyForAlg(%q) error = %v", tt.alg, err)
			}
			if key.Algorithm() != tt.wantAlg {
				t.Errorf("algorithm = %v, want %v", key.Algorithm(), tt.wantAlg)
			}
			var rawKey *ecdsa.PrivateKey
			if err := key.Raw(&rawKey); err != nil {
				t.Fatalf("failed to get raw EC key: %v", err)
			}
			if rawKey.Curve != tt.curve {
				t.Errorf("curve = %v, want %v", rawKey.Curve, tt.curve)
			}
		})
	}
}

func TestGenerateDPoPKeyForAlg_RSA(t *testing.T) {
	tests := []struct {
		alg     string
		wantAlg jwa.SignatureAlgorithm
	}{
		{dpopAlgRS256, jwa.RS256},
		{dpopAlgRS384, jwa.RS384},
		{dpopAlgRS512, jwa.RS512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			key, err := generateDPoPKeyForAlg(tt.alg)
			if err != nil {
				t.Fatalf("generateDPoPKeyForAlg(%q) error = %v", tt.alg, err)
			}
			if key.Algorithm() != tt.wantAlg {
				t.Errorf("algorithm = %v, want %v", key.Algorithm(), tt.wantAlg)
			}
			var rawKey *rsa.PrivateKey
			if err := key.Raw(&rawKey); err != nil {
				t.Fatalf("failed to get raw RSA key: %v", err)
			}
		})
	}
}

func TestGenerateDPoPKeyForAlg_Invalid(t *testing.T) {
	for _, alg := range []string{"INVALID", "", "HS256", "PS256"} {
		t.Run(alg, func(t *testing.T) {
			_, err := generateDPoPKeyForAlg(alg)
			if err == nil {
				t.Errorf("expected error for alg %q, got nil", alg)
			}
		})
	}
}

func TestLoadDPoPKeyFromPEM_RSA(t *testing.T) {
	generated, err := generateDPoPKeyForAlg(dpopAlgRS256)
	if err != nil {
		t.Fatalf("failed to generate RSA test key: %v", err)
	}
	pemBytes := jwkToPEMForTest(t, generated)

	loaded, err := loadDPoPKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("loadDPoPKeyFromPEM error = %v", err)
	}
	if loaded.Algorithm() != jwa.RS256 {
		t.Errorf("algorithm = %v, want RS256", loaded.Algorithm())
	}
}

func TestLoadDPoPKeyFromPEM_EC(t *testing.T) {
	tests := []struct {
		alg     string
		wantAlg jwa.SignatureAlgorithm
	}{
		{dpopAlgES256, jwa.ES256},
		{dpopAlgES384, jwa.ES384},
		{dpopAlgES512, jwa.ES512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			generated, err := generateDPoPKeyForAlg(tt.alg)
			if err != nil {
				t.Fatalf("failed to generate EC test key: %v", err)
			}
			pemBytes := jwkToPEMForTest(t, generated)

			loaded, err := loadDPoPKeyFromPEM(pemBytes)
			if err != nil {
				t.Fatalf("loadDPoPKeyFromPEM error = %v", err)
			}
			if loaded.Algorithm() != tt.wantAlg {
				t.Errorf("algorithm = %v, want %v", loaded.Algorithm(), tt.wantAlg)
			}
		})
	}
}

func TestLoadDPoPKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := loadDPoPKeyFromPEM([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}
