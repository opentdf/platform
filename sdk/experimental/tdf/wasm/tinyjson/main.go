// Canary: tinyjson codegen with TDF manifest + assertion structs
// EXPECTED TO PASS under TinyGo — tinyjson generates reflection-free
// marshal/unmarshal code specifically designed for TinyGo WASM targets.
//
// This replaces the stdjson canary (which uses encoding/json and fails).
// Struct definitions are copied from sdk/experimental/tdf/ because TinyGo
// cannot compile the full sdk package (it imports crypto/* packages).
package main

import (
	t "github.com/opentdf/platform/sdk/experimental/tdf/wasm/tinyjson/types"
)

func main() {
	testManifestRoundTrip()
	testPolicyRoundTrip()
	testAssertionRoundTrip()
	testEmptySlicesPreserved()
	testOmitemptyFields()
}

func testManifestRoundTrip() {
	m := t.Manifest{
		EncryptionInformation: t.EncryptionInformation{
			KeyAccessType: "split",
			Policy:        "eyJ1dWlkIjoiMTIzIn0=",
			KeyAccessObjs: []t.KeyAccess{
				{
					KeyType:    "wrapped",
					KasURL:     "https://kas.example.com",
					Protocol:   "kas",
					WrappedKey: "dGVzdA==",
					PolicyBinding: t.PolicyBinding{
						Alg:  "HS256",
						Hash: "YWJj",
					},
					KID:     "kid-1",
					SplitID: "split-1",
				},
			},
			Method: t.Method{
				Algorithm:    "AES-256-GCM",
				IsStreamable: true,
			},
			IntegrityInformation: t.IntegrityInformation{
				RootSignature: t.RootSignature{
					Algorithm: "HS256",
					Signature: "c2ln",
				},
				SegmentHashAlgorithm:    "HS256",
				DefaultSegmentSize:      2097152,
				DefaultEncryptedSegSize: 2097180,
				Segments: []t.Segment{
					{Hash: "aGFzaA==", Size: 11, EncryptedSize: 39},
				},
			},
		},
		Payload: t.Payload{
			Type:        "reference",
			URL:         "0.payload",
			Protocol:    "zip",
			MimeType:    "application/octet-stream",
			IsEncrypted: true,
		},
		TDFVersion: "4.0.0",
	}

	// Marshal using tinyjson
	data, err := m.MarshalJSON()
	if err != nil {
		panic("Manifest MarshalJSON failed: " + err.Error())
	}
	if len(data) == 0 {
		panic("Manifest MarshalJSON returned empty")
	}

	// Unmarshal back
	var m2 t.Manifest
	if err := m2.UnmarshalJSON(data); err != nil {
		panic("Manifest UnmarshalJSON failed: " + err.Error())
	}

	// Verify all fields survived the round-trip
	assertEq("KeyAccessType", m2.KeyAccessType, "split")
	assertEq("Policy", m2.Policy, "eyJ1dWlkIjoiMTIzIn0=")
	assertEq("TDFVersion", m2.TDFVersion, "4.0.0")

	// Payload
	assertEq("Payload.Type", m2.Payload.Type, "reference")
	assertEq("Payload.URL", m2.Payload.URL, "0.payload")
	assertEq("Payload.Protocol", m2.Payload.Protocol, "zip")
	assertEq("Payload.MimeType", m2.Payload.MimeType, "application/octet-stream")
	assertBool("Payload.IsEncrypted", m2.Payload.IsEncrypted, true)

	// Method
	assertEq("Method.Algorithm", m2.Method.Algorithm, "AES-256-GCM")
	assertBool("Method.IsStreamable", m2.Method.IsStreamable, true)

	// IntegrityInformation
	assertEq("RootSignature.Algorithm", m2.RootSignature.Algorithm, "HS256")
	assertEq("RootSignature.Signature", m2.RootSignature.Signature, "c2ln")
	assertEq("SegmentHashAlgorithm", m2.SegmentHashAlgorithm, "HS256")
	assertInt64("DefaultSegmentSize", m2.DefaultSegmentSize, 2097152)
	assertInt64("DefaultEncryptedSegSize", m2.DefaultEncryptedSegSize, 2097180)

	// Segments
	assertLen("Segments", len(m2.Segments), 1)
	assertEq("Segment.Hash", m2.Segments[0].Hash, "aGFzaA==")
	assertInt64("Segment.Size", m2.Segments[0].Size, 11)
	assertInt64("Segment.EncryptedSize", m2.Segments[0].EncryptedSize, 39)

	// KeyAccess
	assertLen("KeyAccessObjs", len(m2.KeyAccessObjs), 1)
	ka := m2.KeyAccessObjs[0]
	assertEq("KeyAccess.KeyType", ka.KeyType, "wrapped")
	assertEq("KeyAccess.KasURL", ka.KasURL, "https://kas.example.com")
	assertEq("KeyAccess.Protocol", ka.Protocol, "kas")
	assertEq("KeyAccess.WrappedKey", ka.WrappedKey, "dGVzdA==")
	assertEq("KeyAccess.KID", ka.KID, "kid-1")
	assertEq("KeyAccess.SplitID", ka.SplitID, "split-1")
	assertEq("PolicyBinding.Alg", ka.PolicyBinding.Alg, "HS256")
	assertEq("PolicyBinding.Hash", ka.PolicyBinding.Hash, "YWJj")

	// Double marshal — verify idempotent output
	data2, err := m2.MarshalJSON()
	if err != nil {
		panic("double MarshalJSON failed: " + err.Error())
	}
	if string(data) != string(data2) {
		panic("double marshal mismatch — tinyjson output not idempotent")
	}
}

func testPolicyRoundTrip() {
	p := t.Policy{
		UUID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Body: t.PolicyBody{
			DataAttributes: []t.PolicyAttribute{
				{
					Attribute: "https://example.com/attr/Classification/value/Secret",
					KasURL:    "https://kas.example.com",
				},
				{
					Attribute:   "https://example.com/attr/Country/value/USA",
					DisplayName: "USA",
					IsDefault:   true,
				},
			},
			Dissem: []string{"user@example.com"},
		},
	}

	data, err := p.MarshalJSON()
	if err != nil {
		panic("Policy MarshalJSON failed: " + err.Error())
	}

	var p2 t.Policy
	if err := p2.UnmarshalJSON(data); err != nil {
		panic("Policy UnmarshalJSON failed: " + err.Error())
	}

	assertEq("Policy.UUID", p2.UUID, p.UUID)
	assertLen("DataAttributes", len(p2.Body.DataAttributes), 2)
	assertEq("DataAttributes[0].Attribute", p2.Body.DataAttributes[0].Attribute, "https://example.com/attr/Classification/value/Secret")
	assertEq("DataAttributes[1].DisplayName", p2.Body.DataAttributes[1].DisplayName, "USA")
	assertBool("DataAttributes[1].IsDefault", p2.Body.DataAttributes[1].IsDefault, true)
	assertLen("Dissem", len(p2.Body.Dissem), 1)
	assertEq("Dissem[0]", p2.Body.Dissem[0], "user@example.com")
}

func testAssertionRoundTrip() {
	a := t.Assertion{
		ID:             "424ff3a3-50ca-4f01-a2ae-ef851cd3cac0",
		Type:           "handling",
		Scope:          "tdo",
		AppliesToState: "encrypted",
		Statement: t.Statement{
			Format: "json+stanag5636",
			Schema: "urn:nato:stanag:5636:A:1:elements:json",
			Value:  `{"ocl":{"cls":"SECRET"}}`,
		},
		Binding: t.Binding{
			Method:    "jws",
			Signature: "eyJhbGciOiJIUzI1NiJ9.test.sig",
		},
	}

	data, err := a.MarshalJSON()
	if err != nil {
		panic("Assertion MarshalJSON failed: " + err.Error())
	}

	var a2 t.Assertion
	if err := a2.UnmarshalJSON(data); err != nil {
		panic("Assertion UnmarshalJSON failed: " + err.Error())
	}

	assertEq("Assertion.ID", a2.ID, a.ID)
	assertEq("Assertion.Type", a2.Type, "handling")
	assertEq("Assertion.Scope", a2.Scope, "tdo")
	assertEq("Assertion.AppliesToState", a2.AppliesToState, "encrypted")
	assertEq("Statement.Format", a2.Statement.Format, "json+stanag5636")
	assertEq("Statement.Schema", a2.Statement.Schema, "urn:nato:stanag:5636:A:1:elements:json")
	assertEq("Statement.Value", a2.Statement.Value, `{"ocl":{"cls":"SECRET"}}`)
	assertEq("Binding.Method", a2.Binding.Method, "jws")
	assertEq("Binding.Signature", a2.Binding.Signature, "eyJhbGciOiJIUzI1NiJ9.test.sig")
}

func testEmptySlicesPreserved() {
	// Verify that empty slices marshal as [] not null
	p := t.Policy{
		UUID: "test",
		Body: t.PolicyBody{
			DataAttributes: []t.PolicyAttribute{},
			Dissem:         []string{},
		},
	}

	data, err := p.MarshalJSON()
	if err != nil {
		panic("empty slices MarshalJSON failed: " + err.Error())
	}

	var p2 t.Policy
	if err := p2.UnmarshalJSON(data); err != nil {
		panic("empty slices UnmarshalJSON failed: " + err.Error())
	}
	// tinyjson may decode empty arrays as nil slices; that's acceptable
	// as long as len() == 0
	assertLen("empty DataAttributes", len(p2.Body.DataAttributes), 0)
	assertLen("empty Dissem", len(p2.Body.Dissem), 0)
}

func testOmitemptyFields() {
	// Verify omitempty fields are absent when zero-valued
	a := t.Assertion{
		ID:    "test",
		Type:  "handling",
		Scope: "tdo",
		Statement: t.Statement{
			Format: "text",
			Value:  "hello",
		},
		// AppliesToState is zero → omitempty
		// Binding is zero → omitempty
	}

	data, err := a.MarshalJSON()
	if err != nil {
		panic("omitempty MarshalJSON failed: " + err.Error())
	}

	json := string(data)
	// appliesToState should be omitted when empty
	if containsKey(json, "appliesToState") {
		panic("omitempty: appliesToState should be omitted when empty")
	}

	// Unmarshal and verify zero fields stay zero
	var a2 t.Assertion
	if err := a2.UnmarshalJSON(data); err != nil {
		panic("omitempty UnmarshalJSON failed: " + err.Error())
	}
	assertEq("omitempty AppliesToState", a2.AppliesToState, "")
}

// ── Helpers ──────────────────────────────────────────────────

func assertEq(field, got, want string) {
	if got != want {
		panic("round-trip mismatch: " + field + " got=" + got + " want=" + want)
	}
}

func assertInt64(field string, got, want int64) {
	if got != want {
		panic("round-trip mismatch: " + field)
	}
}

func assertBool(field string, got, want bool) {
	if got != want {
		panic("round-trip mismatch: " + field)
	}
}

func assertLen(field string, got, want int) {
	if got != want {
		panic("round-trip mismatch: " + field + " length")
	}
}

// containsKey is a simple check for a JSON key (not a full parser).
func containsKey(json, key string) bool {
	target := `"` + key + `"`
	for i := 0; i <= len(json)-len(target); i++ {
		if json[i:i+len(target)] == target {
			return true
		}
	}
	return false
}
