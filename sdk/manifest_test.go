package sdk

import (
	"encoding/json"
	"testing"
)

func TestKeyAccessUnmarshalJSON_V43Compat(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantKeyType string
		wantAlg     string
	}{
		{
			name:        "v4.3 wrapped infers RSA-OAEP",
			input:       `{"type":"wrapped","url":"https://kas.example.com","protocol":"kas","wrappedKey":"abc"}`,
			wantKeyType: "wrapped",
			wantAlg:     "RSA-OAEP",
		},
		{
			name:        "v4.3 ec-wrapped infers ECDH-HKDF",
			input:       `{"type":"ec-wrapped","url":"https://kas.example.com","protocol":"kas","wrappedKey":"abc"}`,
			wantKeyType: "ec-wrapped",
			wantAlg:     "ECDH-HKDF",
		},
		{
			name:        "v4.4 explicit alg preserved",
			input:       `{"type":"wrapped","alg":"RSA-OAEP-256","url":"https://kas.example.com","protocol":"kas","wrappedKey":"abc"}`,
			wantKeyType: "wrapped",
			wantAlg:     "RSA-OAEP-256",
		},
		{
			name:        "v4.4 ML-KEM-768 preserved",
			input:       `{"type":"","alg":"ML-KEM-768","url":"https://kas.example.com","wrappedKey":"abc"}`,
			wantKeyType: "",
			wantAlg:     "ML-KEM-768",
		},
		{
			name:        "unknown type does not infer alg",
			input:       `{"type":"remote","url":"https://kas.example.com","wrappedKey":"abc"}`,
			wantKeyType: "remote",
			wantAlg:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ka KeyAccess
			if err := json.Unmarshal([]byte(tt.input), &ka); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if ka.KeyType != tt.wantKeyType {
				t.Errorf("KeyType = %q, want %q", ka.KeyType, tt.wantKeyType)
			}
			if ka.Algorithm != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", ka.Algorithm, tt.wantAlg)
			}
		})
	}
}

func TestKeyAccessMarshalJSON_V44Fields(t *testing.T) {
	ka := KeyAccess{
		KeyType:       "wrapped",
		Algorithm:     "RSA-OAEP",
		KasURL:        "https://kas.example.com",
		Protocol:      "kas",
		WrappedKey:    "abc",
		PolicyBinding: PolicyBinding{Alg: "HS256", Hash: "def"},
		KID:           "k1",
		SplitID:       "s1",
	}

	data, err := json.Marshal(ka)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var roundTrip KeyAccess
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if roundTrip.Algorithm != "RSA-OAEP" {
		t.Errorf("Algorithm = %q, want %q", roundTrip.Algorithm, "RSA-OAEP")
	}
	if roundTrip.KID != "k1" {
		t.Errorf("KID = %q, want %q", roundTrip.KID, "k1")
	}
	if roundTrip.SplitID != "s1" {
		t.Errorf("SplitID = %q, want %q", roundTrip.SplitID, "s1")
	}
}

func TestKeyAccessMarshalJSON_OmitEmptyAlg(t *testing.T) {
	ka := KeyAccess{
		KeyType:       "wrapped",
		KasURL:        "https://kas.example.com",
		Protocol:      "kas",
		WrappedKey:    "abc",
		PolicyBinding: "hash",
	}

	data, err := json.Marshal(ka)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Verify "alg" is not present when empty
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if _, ok := raw["alg"]; ok {
		t.Error("expected alg field to be omitted when empty")
	}
}
