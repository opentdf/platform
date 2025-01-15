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
			name: "upgrade2023CertIDA",
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
			name: "upgrade2023CertIDB",
			config: CryptoConfig2024{
				Standard: Standard{
					RSAKeys: map[string]StandardKeyInfo{
						"r1": {PrivateKeyPath: "r1_private.pem", PublicKeyPath: "r1_public.pem"},
						"r2": {PrivateKeyPath: "r2_private.pem", PublicKeyPath: "r2_public.pem"},
					},
					ECKeys: map[string]StandardKeyInfo{
						"e1": {PrivateKeyPath: "e1_private.pem", PublicKeyPath: "e1_public.pem"},
						"e2": {PrivateKeyPath: "e2_private.pem", PublicKeyPath: "e2_public.pem"},
					},
				},
			},
			input: map[string]any{
				"enabled":   true,
				"eccertid":  "e1",
				"rsacertid": "r1",
			},
			expected: KASConfigDupe{
				Keyring: []CurrentKeyFor{
					{Algorithm: "rsa:2048", KID: "r1", Private: "r1_private.pem", Certificate: "r1_public.pem", Active: true, Legacy: true},
					{Algorithm: "rsa:2048", KID: "r2", Private: "r2_private.pem", Certificate: "r2_public.pem", Active: false, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "e1", Private: "e1_private.pem", Certificate: "e1_public.pem", Active: true, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "e2", Private: "e2_private.pem", Certificate: "e2_public.pem", Active: false, Legacy: true},
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
			name: "upgrade2024H2A",
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
					{"alg": "rsa:2048", "kid": "rsa1"},
					{"alg": "ec:secp256r1", "kid": "ec1"},
					{"alg": "rsa:2048", "kid": "rsa1", "legacy": true},
					{"alg": "ec:secp256r1", "kid": "ec1", "legacy": true},
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
			name: "upgrade2024H2A",
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
					{"alg": "rsa:2048", "kid": "rsa1"},
					{"alg": "ec:secp256r1", "kid": "ec1"},
				},
			},
			expected: KASConfigDupe{
				Keyring: []CurrentKeyFor{
					{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem", Active: true, Legacy: false},
					{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem", Active: true, Legacy: false},
				},
			},
			wantErr: false,
		},
		{
			name: "upgrade2024H2B",
			config: CryptoConfig2024{
				Standard: Standard{
					Keys: []KeyPairInfo{
						{Algorithm: "ec:secp256r1", KID: "ec2", Private: "ec2_private.pem", Certificate: "ec2_public.pem"},
						{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem"},
						{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem"},
						{Algorithm: "rsa:2048", KID: "rsa3", Private: "rsa3_private.pem", Certificate: "rsa3_public.pem"},
						{Algorithm: "rsa:2048", KID: "rsa2", Private: "rsa2_private.pem", Certificate: "rsa2_public.pem"},
						{Algorithm: "ec:secp256r1", KID: "ec3", Private: "ec3_private.pem", Certificate: "ec3_public.pem"},
					},
				},
			},
			input: map[string]any{
				"keyring": []map[string]any{
					{"alg": "rsa:2048", "kid": "rsa1"},
					{"alg": "ec:secp256r1", "kid": "ec1", "legacy": true},
					{"alg": "ec:secp256r1", "kid": "ec1"},
					{"alg": "rsa:2048", "kid": "rsa2", "legacy": true},
					{"alg": "ec:secp256r1", "kid": "ec2", "legacy": true},
				},
			},
			expected: KASConfigDupe{
				Keyring: []CurrentKeyFor{
					{Algorithm: "rsa:2048", KID: "rsa1", Private: "rsa1_private.pem", Certificate: "rsa1_public.pem", Active: true, Legacy: false},
					{Algorithm: "rsa:2048", KID: "rsa2", Private: "rsa2_private.pem", Certificate: "rsa2_public.pem", Active: false, Legacy: true},
					{Algorithm: "rsa:2048", KID: "rsa3", Private: "rsa3_private.pem", Certificate: "rsa3_public.pem", Active: false, Legacy: false},
					{Algorithm: "ec:secp256r1", KID: "ec1", Private: "ec1_private.pem", Certificate: "ec1_public.pem", Active: true, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "ec2", Private: "ec2_private.pem", Certificate: "ec2_public.pem", Active: false, Legacy: true},
					{Algorithm: "ec:secp256r1", KID: "ec3", Private: "ec3_private.pem", Certificate: "ec3_public.pem", Active: false, Legacy: false},
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
			assert.ElementsMatch(t, tt.expected.Keyring, result.Keyring)
		})
	}
}
