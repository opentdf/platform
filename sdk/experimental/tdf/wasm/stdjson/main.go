// Canary: encoding/json with TDF manifest structs
// EXPECTED TO FAIL under TinyGo — encoding/json requires reflect features
// that TinyGo has not implemented. This canary tracks when/if TinyGo fixes
// this, and will be replaced by tinyjson codegen in the spike.
//
// These structs are copied from sdk/experimental/tdf/manifest.go because
// TinyGo cannot compile the full sdk package (it imports crypto/* packages).
package main

import (
	"encoding/json"
)

// Manifest structs — copied from sdk/experimental/tdf/manifest.go

type Segment struct {
	Hash          string `json:"hash"`
	Size          int64  `json:"segmentSize"`
	EncryptedSize int64  `json:"encryptedSegmentSize"`
}

type RootSignature struct {
	Algorithm string `json:"alg"`
	Signature string `json:"sig"`
}

type IntegrityInformation struct {
	RootSignature           `json:"rootSignature"`
	SegmentHashAlgorithm    string    `json:"segmentHashAlg"`
	DefaultSegmentSize      int64     `json:"segmentSizeDefault"`
	DefaultEncryptedSegSize int64     `json:"encryptedSegmentSizeDefault"`
	Segments                []Segment `json:"segments"`
}

type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
}

type KeyAccess struct {
	KeyType            string      `json:"type"`
	KasURL             string      `json:"url"`
	Protocol           string      `json:"protocol"`
	WrappedKey         string      `json:"wrappedKey"`
	PolicyBinding      interface{} `json:"policyBinding"`
	EncryptedMetadata  string      `json:"encryptedMetadata,omitempty"`
	KID                string      `json:"kid,omitempty"`
	SplitID            string      `json:"sid,omitempty"`
	SchemaVersion      string      `json:"schemaVersion,omitempty"`
	EphemeralPublicKey string      `json:"ephemeralPublicKey,omitempty"`
}

type Method struct {
	Algorithm    string `json:"algorithm"`
	IV           string `json:"iv"`
	IsStreamable bool   `json:"isStreamable"`
}

type Payload struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	MimeType    string `json:"mimeType"`
	IsEncrypted bool   `json:"isEncrypted"`
}

type EncryptionInformation struct {
	KeyAccessType        string      `json:"type"`
	Policy               string      `json:"policy"`
	KeyAccessObjs        []KeyAccess `json:"keyAccess"`
	Method               Method      `json:"method"`
	IntegrityInformation `json:"integrityInformation"`
}

type Manifest struct {
	EncryptionInformation `json:"encryptionInformation"`
	Payload               `json:"payload"`
	TDFVersion            string `json:"schemaVersion,omitempty"`
}

func main() {
	m := Manifest{
		EncryptionInformation: EncryptionInformation{
			KeyAccessType: "split",
			Policy:        "eyJ1dWlkIjoiMTIzIn0=",
			KeyAccessObjs: []KeyAccess{
				{
					KeyType:    "wrapped",
					KasURL:     "https://kas.example.com",
					Protocol:   "kas",
					WrappedKey: "dGVzdA==",
					PolicyBinding: PolicyBinding{
						Alg:  "HS256",
						Hash: "YWJj",
					},
				},
			},
			Method: Method{
				Algorithm:    "AES-256-GCM",
				IsStreamable: true,
			},
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Algorithm: "HS256",
					Signature: "c2ln",
				},
				SegmentHashAlgorithm:    "HS256",
				DefaultSegmentSize:      2097152,
				DefaultEncryptedSegSize: 2097180,
				Segments: []Segment{
					{Hash: "aGFzaA==", Size: 11, EncryptedSize: 39},
				},
			},
		},
		Payload: Payload{
			Type:        "reference",
			URL:         "0.payload",
			Protocol:    "zip",
			MimeType:    "application/octet-stream",
			IsEncrypted: true,
		},
	}

	// Marshal
	data, err := json.Marshal(m)
	if err != nil {
		panic("json.Marshal failed: " + err.Error())
	}

	// Unmarshal
	var m2 Manifest
	if err := json.Unmarshal(data, &m2); err != nil {
		panic("json.Unmarshal failed: " + err.Error())
	}

	// Verify round-trip
	if m2.EncryptionInformation.KeyAccessType != "split" {
		panic("round-trip mismatch: KeyAccessType")
	}
	if len(m2.EncryptionInformation.KeyAccessObjs) != 1 {
		panic("round-trip mismatch: KeyAccessObjs length")
	}
	if m2.Payload.URL != "0.payload" {
		panic("round-trip mismatch: Payload.URL")
	}
}
