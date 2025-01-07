package security

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
)

func TestMarshalTo(t *testing.T) {
	tests := []struct {
		name     string
		config   CryptoConfig2024
		input    map[string]any
		expected KASConfigDupe
		wantErr  bool
	}{
		{
			name: "older input (pre-2024, no legacy)",
			config: CryptoConfig2024{
				RSAKeys: map[string]StandardKeyInfo{
					"rsa1": {PrivateKeyPath: "rsa1_private.pem", PublicKeyPath: "rsa1_public.pem"},
				},
				ECKeys: map[string]StandardKeyInfo{
					"ec1": {PrivateKeyPath: "ec1_private.pem", PublicKeyPath: "ec1_public.pem"},
				},
			},
			input: map[string]any{
				"eccertid":  "ec1",
				"rsacertid": "rsa1",
			},
			expected: KASConfigDupe{
				Keyring: []CurrentKeyFor{
					{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem", Active: true, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem", Active: true, Legacy: true},
				},
			},
			wantErr: false,
		},
		{
			name: "older input (pre-2024, supports legacy)",
			config: CryptoConfig2024{
				RSAKeys: map[string]StandardKeyInfo{
					"rsa1": {PrivateKeyPath: "rsa1_private.pem", PublicKeyPath: "rsa1_public.pem"},
				},
				ECKeys: map[string]StandardKeyInfo{
					"ec1": {PrivateKeyPath: "ec1_private.pem", PublicKeyPath: "ec1_public.pem"},
				},
			},
			input: map[string]any{},
			expected: KASConfigDupe{
				Keyring: []CurrentKeyFor{
					{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem", Active: true, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem", Active: true, Legacy: true},
				},
			},
			wantErr: false,
		},
		{
			name: "older input (2024)",
			config: CryptoConfig2024{
				Keys: []KeyPairInfo{
					{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem"},
					{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem"},
				},
			},
			input: map[string]any{
				"keyring": []map[string]any{
					{"alg": "rsa:2048", "kid": "rsa1", "private": "rsa1_private.pem", "cert": "rsa1_public.pem", "active": true, "legacy": true},
					{"alg": "ec:secp256r1", "kid": "ec1", "private": "ec1_private.pem", "cert": "ec1_public.pem", "active": true, "legacy": true},
				},
			},
			expected: KASConfigDupe{
				Keyring: []CurrentKeyFor{
					{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem", Active: true, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem", Active: true, Legacy: true},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid input",
			config: CryptoConfig2024{
				RSAKeys: map[string]StandardKeyInfo{},
				ECKeys:  map[string]StandardKeyInfo{},
				Keys:    []KeyPairInfo{},
			},
			input:   map[string]any{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.MarshalTo(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				var result KASConfigDupe
				err = mapstructure.Decode(tt.input, &result)
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
