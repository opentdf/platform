package keysplit

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      policy.Algorithm
		expected string
	}{
		{
			name:     "unspecified algorithm",
			alg:      policy.Algorithm_ALGORITHM_UNSPECIFIED,
			expected: "unknown",
		},
		{
			name:     "EC P256",
			alg:      policy.Algorithm_ALGORITHM_EC_P256,
			expected: "ec:secp256r1",
		},
		{
			name:     "EC P384",
			alg:      policy.Algorithm_ALGORITHM_EC_P384,
			expected: "ec:secp384r1",
		},
		{
			name:     "EC P521",
			alg:      policy.Algorithm_ALGORITHM_EC_P521,
			expected: "ec:secp521r1",
		},
		{
			name:     "RSA 2048",
			alg:      policy.Algorithm_ALGORITHM_RSA_2048,
			expected: "rsa:2048",
		},
		{
			name:     "RSA 4096",
			alg:      policy.Algorithm_ALGORITHM_RSA_4096,
			expected: "rsa:4096",
		},
		{
			name:     "unknown algorithm value",
			alg:      policy.Algorithm(999),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAlgorithm(tt.alg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertAlgEnum2Simple(t *testing.T) {
	tests := []struct {
		name     string
		algEnum  policy.KasPublicKeyAlgEnum
		expected policy.Algorithm
	}{
		{
			name:     "unspecified",
			algEnum:  policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED,
			expected: policy.Algorithm_ALGORITHM_UNSPECIFIED,
		},
		{
			name:     "EC secp256r1",
			algEnum:  policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
			expected: policy.Algorithm_ALGORITHM_EC_P256,
		},
		{
			name:     "EC secp384r1",
			algEnum:  policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1,
			expected: policy.Algorithm_ALGORITHM_EC_P384,
		},
		{
			name:     "EC secp521r1",
			algEnum:  policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1,
			expected: policy.Algorithm_ALGORITHM_EC_P521,
		},
		{
			name:     "RSA 2048",
			algEnum:  policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
			expected: policy.Algorithm_ALGORITHM_RSA_2048,
		},
		{
			name:     "RSA 4096",
			algEnum:  policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096,
			expected: policy.Algorithm_ALGORITHM_RSA_4096,
		},
		{
			name:     "unknown enum value",
			algEnum:  policy.KasPublicKeyAlgEnum(999),
			expected: policy.Algorithm_ALGORITHM_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertAlgEnum2Simple(tt.algEnum)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasValidGrants(t *testing.T) {
	tests := []struct {
		name     string
		grants   []*policy.KeyAccessServer
		kasKeys  []*policy.SimpleKasKey
		expected bool
	}{
		{
			name:     "empty grants and keys",
			grants:   []*policy.KeyAccessServer{},
			kasKeys:  []*policy.SimpleKasKey{},
			expected: false,
		},
		{
			name:   "valid KAS key",
			grants: []*policy.KeyAccessServer{},
			kasKeys: []*policy.SimpleKasKey{
				{
					KasUri: "https://kas.example.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "test-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----",
					},
				},
			},
			expected: true,
		},
		{
			name:   "KAS key with empty URI",
			grants: []*policy.KeyAccessServer{},
			kasKeys: []*policy.SimpleKasKey{
				{
					KasUri: "",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "test-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----",
					},
				},
			},
			expected: false,
		},
		{
			name:   "KAS key with nil public key",
			grants: []*policy.KeyAccessServer{},
			kasKeys: []*policy.SimpleKasKey{
				{
					KasUri:    "https://kas.example.com",
					PublicKey: nil,
				},
			},
			expected: false,
		},
		{
			name: "valid legacy grant",
			grants: []*policy.KeyAccessServer{
				{
					Uri: "https://kas.example.com",
				},
			},
			kasKeys:  []*policy.SimpleKasKey{},
			expected: true,
		},
		{
			name: "legacy grant with empty URI",
			grants: []*policy.KeyAccessServer{
				{
					Uri: "",
				},
			},
			kasKeys:  []*policy.SimpleKasKey{},
			expected: false,
		},
		{
			name: "nil grant in list",
			grants: []*policy.KeyAccessServer{
				nil,
				{
					Uri: "https://kas.example.com",
				},
			},
			kasKeys:  []*policy.SimpleKasKey{},
			expected: true,
		},
		{
			name:   "nil KAS key in list",
			grants: []*policy.KeyAccessServer{},
			kasKeys: []*policy.SimpleKasKey{
				nil,
				{
					KasUri: "https://kas.example.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "test-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----",
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasValidGrants(tt.grants, tt.kasKeys)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractKASGrants(t *testing.T) {
	tests := []struct {
		name     string
		grants   []*policy.KeyAccessServer
		kasKeys  []*policy.SimpleKasKey
		expected []KASGrant
	}{
		{
			name:     "empty inputs",
			grants:   []*policy.KeyAccessServer{},
			kasKeys:  []*policy.SimpleKasKey{},
			expected: []KASGrant{},
		},
		{
			name:   "mapped keys preferred over grants",
			grants: []*policy.KeyAccessServer{{Uri: "https://legacy.kas.com"}},
			kasKeys: []*policy.SimpleKasKey{
				{
					KasUri: "https://mapped.kas.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "mapped-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nMAPPED\n-----END PUBLIC KEY-----",
					},
				},
			},
			expected: []KASGrant{
				{
					URL: "https://mapped.kas.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "mapped-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nMAPPED\n-----END PUBLIC KEY-----",
					},
				},
			},
		},
		{
			name:    "legacy grants with nested KAS keys",
			grants: []*policy.KeyAccessServer{
				{
					Uri: "https://nested.kas.com",
					KasKeys: []*policy.SimpleKasKey{
						{
							PublicKey: &policy.SimpleKasPublicKey{
								Kid: "nested-key",
								Pem: "-----BEGIN PUBLIC KEY-----\nNESTED\n-----END PUBLIC KEY-----",
							},
						},
					},
				},
			},
			kasKeys: []*policy.SimpleKasKey{},
			expected: []KASGrant{
				{
					URL: "https://nested.kas.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "nested-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nNESTED\n-----END PUBLIC KEY-----",
					},
				},
			},
		},
		{
			name: "duplicate KAS URLs filtered",
			kasKeys: []*policy.SimpleKasKey{
				{
					KasUri: "https://dup.kas.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "first-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nFIRST\n-----END PUBLIC KEY-----",
					},
				},
				{
					KasUri: "https://dup.kas.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "second-key", 
						Pem: "-----BEGIN PUBLIC KEY-----\nSECOND\n-----END PUBLIC KEY-----",
					},
				},
			},
			expected: []KASGrant{
				{
					URL: "https://dup.kas.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Kid: "first-key",
						Pem: "-----BEGIN PUBLIC KEY-----\nFIRST\n-----END PUBLIC KEY-----",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractKASGrants(tt.grants, tt.kasKeys)
			assert.Equal(t, len(tt.expected), len(result))
			
			for i, expected := range tt.expected {
				assert.Equal(t, expected.URL, result[i].URL)
				if expected.PublicKey != nil {
					require.NotNil(t, result[i].PublicKey)
					assert.Equal(t, expected.PublicKey.Kid, result[i].PublicKey.Kid)
					assert.Equal(t, expected.PublicKey.Pem, result[i].PublicKey.Pem)
				} else {
					assert.Nil(t, result[i].PublicKey)
				}
			}
		})
	}
}

func TestResolveAttributeGrants_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		value   *policy.Value
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil value",
			value:   nil,
			wantErr: true,
			errMsg:  "value is nil",
		},
		{
			name: "value with nil attribute",
			value: &policy.Value{
				Id:        "test",
				Fqn:       "https://test.com/attr/test/value/test",
				Attribute: nil,
			},
			wantErr: true,
			errMsg:  "no grants found",
		},
		{
			name: "attribute with nil namespace",
			value: &policy.Value{
				Id:  "test",
				Fqn: "https://test.com/attr/test/value/test",
				Attribute: &policy.Attribute{
					Id:        "test-attr",
					Name:      "test",
					Namespace: nil,
				},
			},
			wantErr: true,
			errMsg:  "no grants found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveAttributeGrants(tt.value)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCollectAllPublicKeys(t *testing.T) {
	assignments := []SplitAssignment{
		{
			SplitID: "split1",
			KASURLs: []string{"https://kas1.com"},
			Keys: map[string]*policy.SimpleKasPublicKey{
				"https://kas1.com": {
					Kid:       "key1",
					Pem:       "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
					Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
				},
			},
		},
		{
			SplitID: "split2",
			KASURLs: []string{"https://kas2.com"},
			Keys: map[string]*policy.SimpleKasPublicKey{
				"https://kas2.com": {
					Kid:       "key2",
					Pem:       "-----BEGIN PUBLIC KEY-----\nKEY2\n-----END PUBLIC KEY-----",
					Algorithm: policy.Algorithm_ALGORITHM_EC_P256,
				},
			},
		},
		{
			SplitID: "split3",
			KASURLs: []string{"https://kas3.com"},
			Keys: map[string]*policy.SimpleKasPublicKey{
				"https://kas3.com": nil, // nil key should be skipped
			},
		},
	}

	result := collectAllPublicKeys(assignments)

	expected := map[string]KASPublicKey{
		"https://kas1.com": {
			URL:       "https://kas1.com",
			KID:       "key1",
			PEM:       "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
			Algorithm: "rsa:2048",
		},
		"https://kas2.com": {
			URL:       "https://kas2.com",
			KID:       "key2",
			PEM:       "-----BEGIN PUBLIC KEY-----\nKEY2\n-----END PUBLIC KEY-----",
			Algorithm: "ec:secp256r1",
		},
	}

	assert.Equal(t, expected, result)
}