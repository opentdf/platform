package security

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "upgrade2023CertID",
			config: CryptoConfig2024{
				Standard: Standard{
					RSAKeys: map[string]StandardKeyInfo{
						"rsa1": {PrivateKeyPath: "rsa1_private.pem", PublicKeyPath: "rsa1_public.pem"},
					},
					ECKeys: map[string]StandardKeyInfo{
						"ec1": {PrivateKeyPath: "ec1_private.pem", PublicKeyPath: "ec1_public.pem"},
						"ec2": {PrivateKeyPath: "ec2_private.pem", PublicKeyPath: "ec2_public.pem"},
					},
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
					{Algorithm: "ec:secp256r1", KID: "ec2", Private: "ec2_private.pem", Certificate: "ec2_public.pem", Active: false, Legacy: true},
				},
			},
			wantErr: false,
		},
		{
			name: "upgrade2023NoCertIDs",
			config: CryptoConfig2024{
				Standard: Standard{
					RSAKeys: map[string]StandardKeyInfo{
						"rsa1": {PrivateKeyPath: "rsa1_private.pem", PublicKeyPath: "rsa1_public.pem"},
					},
					ECKeys: map[string]StandardKeyInfo{
						"ec1": {PrivateKeyPath: "ec1_private.pem", PublicKeyPath: "ec1_public.pem"},
					},
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
			name: "upgrade2024H2",
			config: CryptoConfig2024{
				Standard: Standard{
					Keys: []KeyPairInfo{
						{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem"},
						{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem"},
					},
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
			name: "invalid input confusing",
			config: CryptoConfig2024{
				Standard: Standard{
					RSAKeys: map[string]StandardKeyInfo{},
					ECKeys:  map[string]StandardKeyInfo{},
					Keys:    []KeyPairInfo{},
				},
			},
			input: map[string]any{
				"keyring": []map[string]any{
					{"alg": "rsa:2048", "kid": "rsa1", "private": "rsa1_private.pem", "cert": "rsa1_public.pem", "active": true, "legacy": true},
				},
				"rsacertid": "rsa1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.MarshalTo(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var result KASConfigDupe
			err = mapstructure.Decode(tt.input, &result)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
