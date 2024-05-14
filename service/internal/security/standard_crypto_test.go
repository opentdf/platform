package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStandardCrypto(t *testing.T) {
	tests := []struct {
		name       string
		config     StandardConfig
		setupMocks func()
		wantErr    bool
	}{
		{
			name: "failed RSA keys creation - IO read error",
			config: StandardConfig{
				RSAKeys: map[string]StandardKeyInfo{
					"key1": {
						PrivateKeyPath: "privateKey.pem",
						PublicKeyPath:  "publicKey.pem",
					},
				},
			},
			setupMocks: func() {
			},
			wantErr: true,
		},
		{
			name: "failed EC keys creation - IO read error",
			config: StandardConfig{
				ECKeys: map[string]StandardKeyInfo{
					"key1": {
						PrivateKeyPath: "privateKey.pem",
						PublicKeyPath:  "publicKey.pem",
					},
				},
			},
			setupMocks: func() {
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock functions
			tt.setupMocks()

			_, err := NewStandardCrypto(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateNanoTDFSessionKey(t *testing.T) {
	ecKeyPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKey := StandardECCrypto{
		ecPrivateKey:     ecKeyPrivateKey,
		ecCertificatePEM: "",
		Identifier:       "Test EC Key",
	}

	s := StandardCrypto{
		ecKeys:  []StandardECCrypto{ecKey},
		rsaKeys: nil,
	}

	tests := []struct {
		name        string
		privKey     PrivateKeyEC
		pubKeyBytes []byte
		valid       bool
	}{
		{
			name:        "valid case",
			privKey:     0,
			pubKeyBytes: generateDummyPublicKey(t),
			valid:       true,
		},
		{
			name:        "invalid private key",
			privKey:     123,
			pubKeyBytes: generateDummyPublicKey(t),
			valid:       false,
		},
		{
			name:        "invalid public key bytes",
			privKey:     0,
			pubKeyBytes: []byte("InvalidPublicKey"),
			valid:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.GenerateNanoTDFSessionKey(tt.privKey, tt.pubKeyBytes)
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Utility to generate dummy public key for testing purposes
func generateDummyPublicKey(t *testing.T) []byte {
	// prepare private key template
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	// generate private key
	privKey, err := ecdsa.GenerateKey(privKey.PublicKey.Curve, rand.Reader)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	return pubKeyBytes
}

func TestGenerateEphemeralKasKeys(t *testing.T) {
	s := &StandardCrypto{}

	tests := []struct {
		name   string
		expect func(t *testing.T, priv PrivateKeyEC, pub []byte)
	}{
		{
			name: "Success",
			expect: func(t *testing.T, priv PrivateKeyEC, pub []byte) {
				assert.NotEmpty(t, pub)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, pub, err := s.GenerateEphemeralKasKeys()
			require.NoError(t, err)
			tc.expect(t, priv, pub)
		})
	}
}

func (s StandardCrypto) ecKeyExists() (bool, *ecdsa.PrivateKey) {
	keyExists := false
	var generatedKey *ecdsa.PrivateKey

	if len(s.ecKeys) > 0 {
		keyExists = true
		generatedKey = s.ecKeys[0].ecPrivateKey
	}

	return keyExists, generatedKey
}

func validKeyPair(key *ecdsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("private key is nil")
	}
	dBytes := make([]byte, 32)
	if _, err := rand.Read(dBytes); err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	msg := append(dBytes[:0:0], dBytes...)

	r, s, err := ecdsa.Sign(rand.Reader, key, msg)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	valid := ecdsa.Verify(&key.PublicKey, msg, r, s)
	if !valid {
		return fmt.Errorf("failed to verify signature")
	}

	return nil
}

func TestGenerateEphemeralKasKeys_ValidKeyPair(t *testing.T) {
	s := &StandardCrypto{}
	assert := assert.New(t)
	_, pubBytes, err := s.GenerateEphemeralKasKeys()
	assert.NoError(err)
	assert.NotEmpty(pubBytes)
}

func TestGenerateEphemeralKasKeys_VerifyPublicKey(t *testing.T) {
	s := &StandardCrypto{}

	assert := assert.New(t)

	_, pubBytes, err := s.GenerateEphemeralKasKeys()
	assert.NoError(err)

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubBytes)
	assert.NoError(err)

	_, ok := pubKeyInterface.(*ecdsa.PublicKey)
	assert.True(ok)
}
