package sdk

import (
	"encoding/json"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests capture a cross-implementation (interop) defect around the
// optional assertion field `appliesToState`.
//
// Assertion.GetHash hashes a re-serialization of the Go struct rather than the
// assertion bytes as they were received. Because Assertion.AppliesToState is
// tagged `omitempty`, a producer that writes the field as `null` or `""` has it
// silently dropped by the Go SDK before the hash is recomputed. The recomputed
// hash then differs from the hash the producer signed, and reading the TDF
// fails with "assertion hash missmatch".
//
// The same root cause affects any assertion encoding the struct cannot
// round-trip byte-for-byte (unknown vendor fields, empty/null statement fields,
// object-valued statements), but these tests are scoped to the reported
// appliesToState case.

// hashAsProducer computes the assertion hash the way a non-Go producer does:
// over the assertion JSON as written, rather than over a Go struct that has
// been unmarshaled and re-marshaled. This mirrors the steps in
// Assertion.GetHash (drop `binding`, JCS-canonicalize, SHA-256 as hex).
func hashAsProducer(t *testing.T, rawAssertion string) string {
	t.Helper()

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rawAssertion), &obj))
	delete(obj, "binding")

	canonical, err := json.Marshal(obj)
	require.NoError(t, err)

	transformed, err := jcs.Transform(canonical)
	require.NoError(t, err)

	return string(ocrypto.SHA256AsHex(transformed))
}

// manifestWithAssertion wraps a single assertion in the smallest manifest the
// bundled JSON schemas will otherwise accept.
func manifestWithAssertion(rawAssertion string) string {
	return `{
		"payload": {"type": "reference", "url": "0.payload", "protocol": "zip", "isEncrypted": true},
		"encryptionInformation": {
			"type": "split",
			"keyAccess": [],
			"method": {"algorithm": "AES-256-GCM", "isStreamable": true},
			"integrityInformation": {
				"rootSignature": {"alg": "HS256", "sig": "c2ln"},
				"segmentSizeDefault": 2097152,
				"segments": [],
				"encryptedSegmentSizeDefault": 2097180
			},
			"policy": "e30="
		},
		"assertions": [` + rawAssertion + `]
	}`
}

// appliesToStateEncodings enumerates the ways a producer may represent an
// assertion whose appliesToState is unset, alongside the value the Go SDK
// decodes it to.
var appliesToStateEncodings = []struct {
	name string
	raw  string
}{
	{
		name: "populated",
		raw:  `{"id":"a1","type":"handling","scope":"tdo","appliesToState":"unencrypted","statement":{"format":"json","schema":"urn:example","value":"v"}}`,
	},
	{
		name: "omitted",
		raw:  `{"id":"a1","type":"handling","scope":"tdo","statement":{"format":"json","schema":"urn:example","value":"v"}}`,
	},
	{
		name: "explicit null",
		raw:  `{"id":"a1","type":"handling","scope":"tdo","appliesToState":null,"statement":{"format":"json","schema":"urn:example","value":"v"}}`,
	},
	{
		name: "empty string",
		raw:  `{"id":"a1","type":"handling","scope":"tdo","appliesToState":"","statement":{"format":"json","schema":"urn:example","value":"v"}}`,
	},
}

// TestAssertionHashMatchesProducerEncoding asserts that the hash the Go SDK
// recomputes on read equals the hash the producer signed, for every legal
// encoding of an unset appliesToState.
//
// Currently fails for "explicit null" and "empty string": omitempty drops the
// field before rehashing, so the SDK hashes different bytes than were signed.
func TestAssertionHashMatchesProducerEncoding(t *testing.T) {
	for _, encoding := range appliesToStateEncodings {
		t.Run(encoding.name, func(t *testing.T) {
			var assertion Assertion
			require.NoError(t, json.Unmarshal([]byte(encoding.raw), &assertion))

			recomputed, err := assertion.GetHash()
			require.NoError(t, err)

			assert.Equal(t, hashAsProducer(t, encoding.raw), string(recomputed),
				"hash recomputed from the Go struct must match the hash signed over the received bytes")
		})
	}
}

// TestSchemaAcceptedAssertionsVerify asserts the two validation layers agree:
// any assertion the bundled schema accepts must also produce a hash that
// verifies. Today they contradict each other, and no encoding of an unset
// appliesToState satisfies both:
//
//	encoding | lax schema | strict schema | hash
//	omitted  | rejected   | rejected      | verifies
//	null     | accepted   | rejected      | fails
//	""       | accepted   | accepted      | fails
func TestSchemaAcceptedAssertionsVerify(t *testing.T) {
	for _, intensity := range []struct {
		name  string
		value SchemaValidationIntensity
	}{
		{name: "lax", value: Lax},
		{name: "strict", value: Strict},
	} {
		for _, encoding := range appliesToStateEncodings {
			t.Run(intensity.name+"/"+encoding.name, func(t *testing.T) {
				_, schemaErr := isValidManifest(manifestWithAssertion(encoding.raw), intensity.value)
				if schemaErr != nil {
					t.Skipf("rejected by the %s schema, so it never reaches hash verification: %v", intensity.name, schemaErr)
				}

				var assertion Assertion
				require.NoError(t, json.Unmarshal([]byte(encoding.raw), &assertion))

				recomputed, err := assertion.GetHash()
				require.NoError(t, err)

				assert.Equal(t, hashAsProducer(t, encoding.raw), string(recomputed),
					"an assertion accepted by the %s schema must produce a verifiable hash", intensity.name)
			})
		}
	}
}
