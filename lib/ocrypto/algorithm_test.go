package ocrypto

import "testing"

func TestAlgForKeyType(t *testing.T) {
	tests := []struct {
		keyType KeyType
		want    string
	}{
		{RSA2048Key, AlgRSAOAEP},
		{RSA4096Key, AlgRSAOAEP},
		{EC256Key, AlgECDHHKDF},
		{EC384Key, AlgECDHHKDF},
		{EC521Key, AlgECDHHKDF},
		{"", ""},
		{KeyType("unknown"), "unknown"},
	}
	for _, tt := range tests {
		if got := AlgForKeyType(tt.keyType); got != tt.want {
			t.Errorf("AlgForKeyType(%q) = %q, want %q", tt.keyType, got, tt.want)
		}
	}
}

func TestKeyTypeForAlg(t *testing.T) {
	tests := []struct {
		alg  string
		want KeyType
	}{
		{AlgRSAOAEP, RSA2048Key},
		{AlgRSAOAEP256, RSA2048Key},
		{AlgECDHHKDF, EC256Key},
		{"", KeyType("")},
		{"unknown", KeyType("unknown")},
	}
	for _, tt := range tests {
		if got := KeyTypeForAlg(tt.alg); got != tt.want {
			t.Errorf("KeyTypeForAlg(%q) = %q, want %q", tt.alg, got, tt.want)
		}
	}
}

func TestAlgForLegacyType(t *testing.T) {
	tests := []struct {
		legacy string
		want   string
	}{
		{"wrapped", AlgRSAOAEP},
		{"ec-wrapped", AlgECDHHKDF},
		{"", ""},
		{"unknown", ""},
	}
	for _, tt := range tests {
		if got := AlgForLegacyType(tt.legacy); got != tt.want {
			t.Errorf("AlgForLegacyType(%q) = %q, want %q", tt.legacy, got, tt.want)
		}
	}
}
