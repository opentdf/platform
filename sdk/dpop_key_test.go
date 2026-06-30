package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
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

func TestResolveDPoPKey(t *testing.T) {
	ecKey, err := generateDPoPKeyForAlg(dpopAlgES256)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	ecPEM := jwkToPEMForTest(t, ecKey)

	t.Run("empty config returns nil sentinel", func(t *testing.T) {
		key, err := resolveDPoPKey(&config{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != nil {
			t.Errorf("expected nil key for empty config, got %v", key)
		}
	})

	t.Run("preset JWK validated and returned", func(t *testing.T) {
		key, err := resolveDPoPKey(&config{dpopJWK: ecKey})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == nil {
			t.Fatal("expected key, got nil")
		}
	})

	t.Run("PEM path caches into dpopJWK", func(t *testing.T) {
		c := &config{dpopKeyPEM: ecPEM}
		key, err := resolveDPoPKey(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.Algorithm() != jwa.ES256 {
			t.Errorf("alg = %v, want ES256", key.Algorithm())
		}
		if c.dpopJWK == nil {
			t.Error("expected resolved key cached in dpopJWK")
		}
	})

	t.Run("PEM with algorithm override", func(t *testing.T) {
		rsaKey, err := generateDPoPKeyForAlg(dpopAlgRS256)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		c := &config{dpopKeyPEM: jwkToPEMForTest(t, rsaKey), dpopAlgorithm: dpopAlgRS512}
		key, err := resolveDPoPKey(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.Algorithm() != jwa.RS512 {
			t.Errorf("alg = %v, want RS512 override", key.Algorithm())
		}
	})

	t.Run("generate from algorithm", func(t *testing.T) {
		key, err := resolveDPoPKey(&config{dpopAlgorithm: dpopAlgES384})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.Algorithm() != jwa.ES384 {
			t.Errorf("alg = %v, want ES384", key.Algorithm())
		}
	})
}

func TestValidateDPoPKeyAlgorithm(t *testing.T) {
	t.Run("missing algorithm errors", func(t *testing.T) {
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		k, err := jwk.FromRaw(raw)
		if err != nil {
			t.Fatalf("jwk.FromRaw: %v", err)
		}
		if _, err := resolveDPoPKey(&config{dpopJWK: k}); err == nil {
			t.Error("expected error for JWK without algorithm, got nil")
		}
	})

	t.Run("unsupported algorithm errors", func(t *testing.T) {
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		k, err := jwk.FromRaw(raw)
		if err != nil {
			t.Fatalf("jwk.FromRaw: %v", err)
		}
		if err := k.Set(jwk.AlgorithmKey, jwa.HS256); err != nil {
			t.Fatalf("set alg: %v", err)
		}
		if _, err := resolveDPoPKey(&config{dpopJWK: k}); err == nil {
			t.Error("expected error for unsupported algorithm, got nil")
		}
	})
}
