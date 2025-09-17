package ocrypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromPublicPEM(t *testing.T) {
	testCases := []struct {
		name         string
		filename     string
		expectedType KeyType
	}{
		{
			name:         "EC secp256r1 public key",
			filename:     "sample-ec-secp256r1-01-public.pem",
			expectedType: EC256Key,
		},
		{
			name:         "EC secp384r1 public key",
			filename:     "sample-ec-secp384r1-01-public.pem",
			expectedType: EC384Key,
		},
		{
			name:         "EC secp521r1 public key",
			filename:     "sample-ec-secp521r1-01-public.pem",
			expectedType: EC521Key,
		},
		{
			name:         "RSA 2048 public key",
			filename:     "sample-rsa-2048-01-public.pem",
			expectedType: RSA2048Key,
		},
		{
			name:         "RSA 4096 public key",
			filename:     "sample-rsa-4096-01-public.pem",
			expectedType: RSA4096Key,
		},
		{
			name:         "Unsupported RSA 1024 public key",
			filename:     "sample-rsa-1024-01-public.pem",
			expectedType: KeyType("rsa:1024"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Read the PEM file
			testDataPath := filepath.Join("testdata", tc.filename)
			pemData, err := os.ReadFile(testDataPath)
			require.NoError(t, err, "Failed to read test file %s", tc.filename)

			// Load the public key using FromPublicPEM
			encryptor, err := FromPublicPEM(string(pemData))
			require.NoError(t, err, "Failed to load public key from %s", tc.filename)
			require.NotNil(t, encryptor, "Encryptor should not be nil") // Test that KeyType() returns the expected type
			keyType := encryptor.KeyType()
			assert.Equal(t, tc.expectedType, keyType, "KeyType() returned unexpected value for %s", tc.name)

			// Also test that we can get the public key back in PEM format
			pubKeyPEM, err := encryptor.PublicKeyInPemFormat()
			require.NoError(t, err, "Failed to get public key in PEM format")
			assert.NotEmpty(t, pubKeyPEM, "Public key PEM should not be empty")
		})
	}
}

func TestFromPublicPEM_UnsupportedFiles(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
	}{
		{
			name:     "Unsupported EC secp256k1 public key",
			filename: "sample-ec-secp256k1-01-public.pem",
		},
		{
			name:     "Unsupported EC brainpoolP160r1 public key",
			filename: "sample-ec-brainpoolP160r1-01-public.pem",
		},
		{
			name:     "Loading a private key should fail",
			filename: "sample-ec-secp256r1-01-private.pem",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Read the PEM file
			testDataPath := filepath.Join("testdata", tc.filename)
			pemData, err := os.ReadFile(testDataPath)
			require.NoError(t, err, "Failed to read test file %s", tc.filename)

			// Load the public key using FromPublicPEM - should fail for unsupported curves
			_, err = FromPublicPEM(string(pemData))
			assert.Error(t, err, "Expected error for unsupported curve %s", tc.name)
		})
	}
}

func TestFromPublicPEM_InvalidInput(t *testing.T) {
	testCases := []struct {
		name     string
		pemData  string
		errorMsg string
	}{
		{
			name:     "Empty string",
			pemData:  "",
			errorMsg: "failed to parse PEM formatted public key",
		},
		{
			name:     "Invalid PEM format",
			pemData:  "not a pem file",
			errorMsg: "failed to parse PEM formatted public key",
		},
		{
			name: "Invalid PEM content",
			pemData: `-----BEGIN PUBLIC KEY-----
invalid base64 content!!!
-----END PUBLIC KEY-----`,
			errorMsg: "failed to parse PEM formatted public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromPublicPEM(tc.pemData)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorMsg)
		})
	}
}
