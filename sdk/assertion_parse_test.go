package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireAssertionFailure checks that err is an ErrAssertionFailure with
// exactly id and reason, that it is still a tamper error, and that its
// message carries the stable reason text that CLIs and xtest match on.
func requireAssertionFailure(t *testing.T, err error, id string, reason AssertionFailureReason) {
	t.Helper()
	require.Error(t, err)
	var failure ErrAssertionFailure
	require.ErrorAs(t, err, &failure, "error is not an ErrAssertionFailure: %v", err)
	assert.Equal(t, reason, failure.Reason, "reason; error: %v", err)
	assert.Equal(t, id, failure.ID, "id; error: %v", err)
	require.ErrorIs(t, err, ErrTampered)
	assert.Contains(t, err.Error(), "reason="+string(reason))
	assert.Contains(t, err.Error(), "assertion")
	assert.Contains(t, err.Error(), "tamper")
	if id != "" {
		assert.Contains(t, err.Error(), "id: "+id)
	}
}

// specExampleJCS is the JCS form of the first worked example in spec
// Section 4.4.
const specExampleJCS = `{"appliesToState":"unencrypted","id":"classification","scope":"payload",` +
	`"statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json",` +
	`"value":"{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"dcr\":\"2024-10-21T20:47:36Z\"}}"},` +
	`"type":"handling"}`

const specExampleHash = "456d05d6a3f48a14aeee20c8d5f0429d07e5be3f1695fcec2dbc755cd9d64495"

func TestComputeAssertionHashSpecExamples(t *testing.T) {
	t.Run("string statement value", func(t *testing.T) {
		h, err := ComputeAssertionHash([]byte(specExampleJCS))
		require.NoError(t, err)
		assert.Equal(t, specExampleHash, h)
	})

	t.Run("binding is not hashed", func(t *testing.T) {
		withBinding := strings.TrimSuffix(specExampleJCS, "}") + `,"binding":{"method":"jws","signature":"a.b.c"}}`
		h, err := ComputeAssertionHash([]byte(withBinding))
		require.NoError(t, err)
		assert.Equal(t, specExampleHash, h)
	})

	t.Run("member order and whitespace do not matter", func(t *testing.T) {
		reordered := `{ "type" : "handling", "statement": {"value":` +
			`"{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"dcr\":\"2024-10-21T20:47:36Z\"}}",` +
			` "schema":"urn:nato:stanag:5636:A:1:elements:json", "format":"json+stanag5636"},` +
			` "binding": {"signature":"x"}, "scope":"payload", "id":"classification", "appliesToState":"unencrypted" }`
		h, err := ComputeAssertionHash([]byte(reordered))
		require.NoError(t, err)
		assert.Equal(t, specExampleHash, h)
	})

	t.Run("unmodelled member is hashed", func(t *testing.T) {
		extended := strings.TrimSuffix(specExampleJCS, "}") + `,"extensions":{"hash":"deadbeef","note":"coi"}}`
		h, err := ComputeAssertionHash([]byte(extended))
		require.NoError(t, err)
		assert.Equal(t, "a7347ff1c718c0ee7e88558de64389d5e7194990eb6c78662d0bcd9cfb19c7ba", h)
	})

	t.Run("object statement value is hashed as an object", func(t *testing.T) {
		acp240 := `{"id":"3f1c2d9e-8a4b-4c6d-9e0f-1a2b3c4d5e6f","type":"handling","scope":"payload","appliesToState":"encrypted",` +
			`"statement":{"format":"json-structured","schema":"urn:nato:stanag:5636:A:1:elements:json","value":{` +
			`"@context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"},` +
			`"ocl":{"pol":"62c76c68-d73d-4628-8ccc-4c1e18118c22","cls":"CONFIDENTIAL",` +
			`"catl":[{"type":"P","name":"Releasable To","vals":["USA"]}],"dcr":"2026-11-06T12:00:00Z"}}},` +
			`"binding":{"bdo":"opaque"}}`
		h, err := ComputeAssertionHash([]byte(acp240))
		require.NoError(t, err)
		assert.Equal(t, "46853cb52912fd76f3ff90df3936158ee220b8e5973c5d02bb6e50f468596fba", h)

		// The typed view still stringifies the value, but GetHash must not.
		var a Assertion
		require.NoError(t, json.Unmarshal([]byte(acp240), &a))
		got, err := a.GetHash()
		require.NoError(t, err)
		assert.Equal(t, h, string(got))
	})
}

func TestComputeAssertionHashCoversEverythingButTopLevelBinding(t *testing.T) {
	base := `{"id":"a","type":"other","scope":"tdo","statement":{"format":"f","schema":"s","value":"v","extra":"x"},` +
		`"meta":{"hash":"h","binding":"b","signingKey":"k"},"binding":{"method":"jws","signature":"sig"}}`
	baseHash, err := ComputeAssertionHash([]byte(base))
	require.NoError(t, err)

	for name, mutated := range map[string]string{
		"unmodelled statement member": strings.Replace(base, `"extra":"x"`, `"extra":"y"`, 1),
		"nested hash member":          strings.Replace(base, `"hash":"h"`, `"hash":"H"`, 1),
		"nested binding member":       strings.Replace(base, `"binding":"b"`, `"binding":"B"`, 1),
		"nested signingKey member":    strings.Replace(base, `"signingKey":"k"`, `"signingKey":"K"`, 1),
		"removed unmodelled member":   strings.Replace(base, `"meta":{"hash":"h","binding":"b","signingKey":"k"},`, ``, 1),
		"added top-level member":      strings.Replace(base, `"id":"a",`, `"id":"a","note":null,`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, base, mutated)
			h, err := ComputeAssertionHash([]byte(mutated))
			require.NoError(t, err)
			assert.NotEqual(t, baseHash, h)
		})
	}

	t.Run("top-level binding change", func(t *testing.T) {
		h, err := ComputeAssertionHash([]byte(strings.Replace(base, `"signature":"sig"`, `"signature":"other"`, 1)))
		require.NoError(t, err)
		assert.Equal(t, baseHash, h)
	})
}

func TestComputeAssertionHashRejectsSection3Violations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		id     string
		reason AssertionFailureReason
	}{
		{"duplicate member", `{"id":"a","type":"x","type":"y"}`, "a", AssertionReasonDuplicateMember},
		{"escaped duplicate member", `{"id":"a","type":"x","\u0074ype":"y"}`, "a", AssertionReasonDuplicateMember},
		{"duplicate id", `{"id":"a","id":"b"}`, "", AssertionReasonDuplicateMember},
		{"nested duplicate", `{"id":"a","statement":{"value":{"k":1,"k":2}}}`, "a", AssertionReasonDuplicateMember},
		{"id case variant", `{"id":"a","ID":"b"}`, "a", AssertionReasonAmbiguousMember},
		{"alias-only id", `{"Id":"b"}`, "", AssertionReasonAmbiguousMember},
		{"long s case variant", `{"id":"a","ſcope":"tdo"}`, "a", AssertionReasonAmbiguousMember},
		{"statement case variant", `{"id":"a","statement":{"Value":"x"}}`, "a", AssertionReasonAmbiguousMember},
		{"binding case variant", `{"id":"a","binding":{"Signature":"x"}}`, "a", AssertionReasonAmbiguousMember},
		{"lone surrogate", `{"id":"a","statement":{"value":"\uDEAD"}}`, "a", AssertionReasonInvalidJSON},
		{"lone surrogate in a name", `{"id":"a","\uD800x":1}`, "a", AssertionReasonInvalidJSON},
		{"reversed surrogate pair", `{"id":"a","v":"\uDC00\uD800"}`, "a", AssertionReasonInvalidJSON},
		{"escaped noncharacter", `{"id":"a","v":"\uFFFE"}`, "a", AssertionReasonInvalidJSON},
		{"raw noncharacter", "{\"id\":\"a\",\"v\":\"\uFDD0\"}", "a", AssertionReasonInvalidJSON},
		{"supplementary noncharacter", `{"id":"a","v":"\uD83F\uDFFE"}`, "a", AssertionReasonInvalidJSON},
		{"invalid UTF-8", "{\"id\":\"a\",\"v\":\"\xff\"}", "a", AssertionReasonInvalidJSON},
		{"encoded surrogate", "{\"id\":\"a\",\"v\":\"\xed\xa0\x80\"}", "a", AssertionReasonInvalidJSON},
		{"number overflow", `{"id":"a","v":1e400}`, "a", AssertionReasonInvalidJSON},
		{"negative number overflow", `{"id":"a","v":[-1.8e308]}`, "a", AssertionReasonInvalidJSON},
		{"failure before the id", `{"v":"\uDEAD","id":"late"}`, "late", AssertionReasonInvalidJSON},
		{"invalid id is not named", `{"id":"\uDEAD","v":1e400}`, "", AssertionReasonInvalidJSON},
		{"duplicates win over I-JSON", `{"id":"a","v":"\uDEAD","w":1,"w":2}`, "a", AssertionReasonDuplicateMember},
		{"case variants win over I-JSON", `{"id":"a","v":"\uDEAD","Type":1}`, "a", AssertionReasonAmbiguousMember},
		{"not JSON", `{"id":"a",}`, "", AssertionReasonInvalidJSON},
		{"trailing data", `{"id":"a"} x`, "", AssertionReasonInvalidJSON},
		{"not an object", `["id","a"]`, "", AssertionReasonInvalidJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ComputeAssertionHash([]byte(tc.input))
			requireAssertionFailure(t, err, tc.id, tc.reason)
		})
	}

	for _, tc := range []struct{ name, input string }{
		{"dotless i is not a case variant", `{"id":"a","ıd":"b"}`},
		{"variants inside the statement value are not checked", `{"id":"a","statement":{"value":{"ID":1,"Value":2}}}`},
		{"variants inside unmodelled members are not checked", `{"id":"a","ext":{"Binding":1,"ID":2}}`},
		{"surrogate pair", `{"id":"a","v":"\uD83D\uDE00"}`},
		{"underflow is not an overflow", `{"id":"a","v":1e-400}`},
		{"largest double", `{"id":"a","v":1.7976931348623157e308}`},
		{"escaped U+FFFD", `{"id":"a","v":"\uFFFD"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ComputeAssertionHash([]byte(tc.input))
			require.NoError(t, err)
		})
	}
}

func TestParseManifestSection3(t *testing.T) {
	const valid = `{"payload":{"type":"reference"},"encryptionInformation":{"type":"split"},` +
		`"assertions":[{"id":"a","type":"other","statement":{"value":"v"},"binding":{"method":"jws","signature":"s"}}]}`
	require.NoError(t, parseManifestSection3([]byte(valid)))

	for _, tc := range []struct {
		name     string
		manifest string
		id       string
		reason   AssertionFailureReason
	}{
		{"duplicate at the root", `{"payload":{},"payload":{}}`, "", AssertionReasonDuplicateMember},
		{"escaped duplicate at the root", `{"assertions":[],"\u0061ssertions":[]}`, "", AssertionReasonDuplicateMember},
		{"duplicate deep in the manifest", `{"encryptionInformation":{"integrityInformation":{"segments":[{"hash":"a","hash":"b"}]}}}`, "", AssertionReasonDuplicateMember},
		{"duplicate in an assertion", `{"assertions":[{"id":"a","scope":"x","scope":"y"}]}`, "a", AssertionReasonDuplicateMember},
		{"assertions and Assertions", `{"assertions":[],"Assertions":[{"id":"x"}]}`, "", AssertionReasonAmbiguousMember},
		{"Assertions alone", `{"Assertions":[]}`, "", AssertionReasonAmbiguousMember},
		{"id and ID", `{"assertions":[{"id":"classification","ID":"system-metadata"}]}`, "classification", AssertionReasonAmbiguousMember},
		{"second assertion is named", `{"assertions":[{"id":"ok"},{"id":"bad","Binding":{}}]}`, "bad", AssertionReasonAmbiguousMember},
		{"lone surrogate in an assertion", `{"assertions":[{"id":"a","type":"\uDEAD"}]}`, "a", AssertionReasonInvalidJSON},
		{"overflow in an assertion", `{"assertions":[{"id":"a","x":{"y":[1e999]}}]}`, "a", AssertionReasonInvalidJSON},
		{"invalid UTF-8 in an assertion", "{\"assertions\":[{\"id\":\"a\",\"x\":\"\xc3\"}]}", "a", AssertionReasonInvalidJSON},
		{"not JSON", `{"assertions":[`, "", AssertionReasonInvalidJSON},
		{"Payload alone", `{"Payload":{"type":"reference"}}`, "", AssertionReasonAmbiguousMember},
		{"payload and Payload", `{"payload":{},"Payload":{}}`, "", AssertionReasonAmbiguousMember},
		{"SchemaVersion", `{"SchemaVersion":"4.3.0"}`, "", AssertionReasonAmbiguousMember},
		{"tdf_spec_version variant under payload", `{"payload":{"TDF_spec_version":"4.2.2"}}`, "", AssertionReasonAmbiguousMember},
		{"URL in a key access object", `{"encryptionInformation":{"keyAccess":[{"type":"wrapped","URL":"https://kas"}]}}`, "", AssertionReasonAmbiguousMember},
		{"variant in a policy binding", `{"encryptionInformation":{"keyAccess":[{"policyBinding":{"alg":"HS256","Hash":"x"}}]}}`, "", AssertionReasonAmbiguousMember},
		{"long s in integrityInformation", `{"encryptionInformation":{"integrityInformation":{"ſegmentHashAlg":"GMAC"}}}`, "", AssertionReasonAmbiguousMember},
		{"Hash in the second segment", `{"encryptionInformation":{"integrityInformation":{"segments":[{"hash":"a"},{"Hash":"b"}]}}}`, "", AssertionReasonAmbiguousMember},
		{"variant in the root signature", `{"encryptionInformation":{"integrityInformation":{"rootSignature":{"ALG":"HS256"}}}}`, "", AssertionReasonAmbiguousMember},
		{"variant in the method", `{"encryptionInformation":{"method":{"IV":"x"}}}`, "", AssertionReasonAmbiguousMember},
		{"isStreamable and IsStreamable", `{"encryptionInformation":{"method":{"isStreamable":true,"IsStreamable":false}}}`, "", AssertionReasonAmbiguousMember},
		{"unlisted case pair at the root", `{"foo":1,"Foo":2}`, "", AssertionReasonAmbiguousMember},
		{"unlisted case pair with a Kelvin sign", `{"payload":{"kind":1,"\u212Aind":2}}`, "", AssertionReasonAmbiguousMember},
		{"unlisted case pair in an assertion", `{"assertions":[{"id":"a","ext":1,"EXT":2}]}`, "a", AssertionReasonAmbiguousMember},
		{"invalid UTF-8 outside assertions", "{\"payload\":{\"mimeType\":\"text/\xffplain\"},\"assertions\":[]}", "", AssertionReasonInvalidJSON},
		{"invalid UTF-8 in a member name outside assertions", "{\"payload\":{\"\xc3\":1}}", "", AssertionReasonInvalidJSON},
		{"invalid UTF-8 in a non-object assertion", "{\"assertions\":[\"\xed\xa0\x80\"]}", "", AssertionReasonInvalidJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireAssertionFailure(t, parseManifestSection3([]byte(tc.manifest)), tc.id, tc.reason)
		})
	}

	for _, tc := range []struct{ name, manifest string }{
		{"case pairs inside an unlisted member", `{"payload":{"ext":{"Type":"x","type":"y"}},"x-extra":{"A":1,"a":2}}`},
		{"case pairs inside a statement value", `{"assertions":[{"id":"a","statement":{"value":{"Id":1,"id":2,"Value":3}}}]}`},
		{"case pairs inside JSON carried in a string", `{"encryptionInformation":{"policy":"{\"Body\":1,\"body\":2}"}}`},
		{"IsStreamable alone", `{"encryptionInformation":{"method":{"algorithm":"AES-256-GCM","IsStreamable":true}}}`},
		{"policyBinding that is a string", `{"encryptionInformation":{"keyAccess":[{"policyBinding":"abc"}]}}`},
		{"lone surrogates, noncharacters and overflow outside assertions", "{\"payload\":{\"mimeType\":\"\\uDEAD\\uFFFE\uFDD0\",\"n\":1e400},\"assertions\":[]}"},
		{"assertions that are not objects", `{"assertions":[null,"\uDEAD",1e400]}`},
		{"assertions that is not an array", `{"assertions":{"ID":"x"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, parseManifestSection3([]byte(tc.manifest)))
		})
	}

	t.Run("readers leave a manifest that is not JSON to the decoder", func(t *testing.T) {
		require.NoError(t, checkManifestSection3([]byte(`{"assertions":[`)))
		requireAssertionFailure(t, checkManifestSection3([]byte(`{"a":1,"a":2}`)), "", AssertionReasonDuplicateMember)
	})

	t.Run("nesting beyond the decoder's limit", func(t *testing.T) {
		deep := strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1)
		requireAssertionFailure(t, parseManifestSection3([]byte(deep)), "", AssertionReasonInvalidJSON)
		require.NoError(t, checkManifestSection3([]byte(deep)), "left to the decoder, which rejects it too")
		require.False(t, json.Valid([]byte(deep)))
	})
}

// TestStrictScannerAgreesWithEncodingJSON checks that the scanner accepts
// exactly what encoding/json accepts, so a syntax error is never a way
// around the Section 3 checks.
func TestStrictScannerAgreesWithEncodingJSON(t *testing.T) {
	for _, doc := range []string{
		`{}`, `[]`, `""`, `0`, `-0`, `-0.5e-3`, `1E+2`, `true`, `false`, `null`, " \t\r\n{ } ",
		`{"a":[1,2,{"b":null}],"c":"\"\\\/\b\f\n\r\t\u00e9"}`,
		`01`, `1.`, `.5`, `-`, `+1`, `1e`, `1e+`, `0x10`, `NaN`, `Infinity`,
		`{"a" 1}`, `{"a":1,}`, `[1,]`, `{,}`, `[`, `{"a":`, `"abc`, `"\x"`, `"\u12"`, `"\u12G4"`,
		"\"\x01\"", "\ufeff{}", `{} {}`, `nul`, `truex`, `{'a':1}`,
		"\"\xff\"", `"\uDEAD"`,
	} {
		t.Run(doc, func(t *testing.T) {
			_, err := parseStrictJSON([]byte(doc), levelOther, 0)
			var se *jsonSyntaxError
			assert.Equal(t, json.Valid([]byte(doc)), !errors.As(err, &se), "scanner error: %v", err)
		})
	}
}

func TestAssertionUnmarshalKeepsRawAndIsLenient(t *testing.T) {
	t.Run("raw is kept as received", func(t *testing.T) {
		in := `{"id":"a","type":"other","scope":"tdo","statement":{"value":"v"},"x-ext":{"k":[1,2]}}`
		var a Assertion
		require.NoError(t, json.Unmarshal([]byte(in), &a))
		assert.Equal(t, in, string(a.raw))

		// Edits to the typed view do not change the hash of what was received.
		before, err := a.GetHash()
		require.NoError(t, err)
		a.Statement.Value = "changed"
		after, err := a.GetHash()
		require.NoError(t, err)
		assert.Equal(t, before, after)
	})

	t.Run("non-string id leaves the typed id empty", func(t *testing.T) {
		for _, in := range []string{`{"id":5}`, `{"id":null}`, `{"id":{"x":1}}`, `{}`} {
			var a Assertion
			require.NoError(t, json.Unmarshal([]byte(in), &a), in)
			assert.Empty(t, a.ID, in)
		}
	})

	t.Run("non-object binding leaves the typed binding empty", func(t *testing.T) {
		for _, in := range []string{`{"binding":"x"}`, `{"binding":5}`, `{"binding":[]}`, `{"binding":{"method":1,"signature":true}}`} {
			var a Assertion
			require.NoError(t, json.Unmarshal([]byte(in), &a), in)
			assert.Equal(t, Binding{}, a.Binding, in)
		}
		var a Assertion
		require.NoError(t, json.Unmarshal([]byte(`{"binding":{"method":"JWS","signature":"s"}}`), &a))
		assert.Equal(t, Binding{Method: "JWS", Signature: "s"}, a.Binding)
	})

	t.Run("null element is kept as received", func(t *testing.T) {
		var list []Assertion
		require.NoError(t, json.Unmarshal([]byte(`[null]`), &list))
		require.Len(t, list, 1)
		assert.Equal(t, "null", string(list[0].raw))
		_, err := list[0].GetHash()
		requireAssertionFailure(t, err, "", AssertionReasonInvalidJSON)
	})
}

func TestWriterHashMatchesWrittenAssertion(t *testing.T) {
	config := AssertionConfig{
		ID:             "writer",
		Type:           HandlingAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement:      Statement{Format: "json", Schema: "s", Value: `{"b":1,"a":"<&>"}`},
	}
	signed, err := signAssertions(bytes.Repeat([]byte{7}, 32), []AssertionConfig{config}, bytes.Repeat([]byte{1}, 32), false)
	require.NoError(t, err)
	require.Len(t, signed, 1)

	// What the manifest carries, read back the way a reader reads it.
	written, err := json.Marshal(Manifest{Assertions: signed})
	require.NoError(t, err)
	var m Manifest
	require.NoError(t, json.Unmarshal(written, &m))
	require.Len(t, m.Assertions, 1)

	readHash, err := m.Assertions[0].GetHash()
	require.NoError(t, err)
	builtHash, err := signed[0].GetHash()
	require.NoError(t, err)
	assert.Equal(t, builtHash, readHash)

	claimed, _, err := m.Assertions[0].Verify(AssertionKey{Alg: AssertionKeyAlgHS256, Key: bytes.Repeat([]byte{1}, 32)})
	require.NoError(t, err)
	assert.Equal(t, string(readHash), claimed)
}

func TestLoadTDFRejectsSection3Violations(t *testing.T) {
	s := newLoadTestSDK()
	withAssertions := func(assertions string) string {
		return strings.TrimSuffix(minimalManifestJSON, "}") + `,"assertions":` + assertions + `}`
	}

	for _, tc := range []struct {
		name     string
		manifest string
		id       string
		reason   AssertionFailureReason
	}{
		{"duplicate member", withAssertions(`[{"id":"a","statement":{"value":"x","value":"y"}}]`), "a", AssertionReasonDuplicateMember},
		{"escaped duplicate id", withAssertions(`[{"id":"a","\u0069d":"b"}]`), "", AssertionReasonDuplicateMember},
		{"duplicate outside assertions", strings.Replace(minimalManifestJSON, `"protocol":"zip"`, `"protocol":"zip","protocol":"zip"`, 1), "", AssertionReasonDuplicateMember},
		{"Assertions", strings.TrimSuffix(minimalManifestJSON, "}") + `,"assertions":[],"Assertions":[{"id":"x"}]}`, "", AssertionReasonAmbiguousMember},
		{"ID", withAssertions(`[{"id":"classification","ID":"system-metadata"}]`), "classification", AssertionReasonAmbiguousMember},
		{"lone surrogate", withAssertions(`[{"id":"a","statement":{"value":"\uDEAD"}}]`), "a", AssertionReasonInvalidJSON},
		{"number overflow", withAssertions(`[{"id":"a","n":1e400}]`), "a", AssertionReasonInvalidJSON},
		{"invalid UTF-8 outside assertions", strings.Replace(minimalManifestJSON, `"zip"`, "\"z\xffip\"", 1), "", AssertionReasonInvalidJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := zipWithManifest(t, tc.manifest)
			for _, disable := range []bool{false, true} {
				_, err := s.LoadTDF(bytes.NewReader(data), WithDisableAssertionVerification(disable), WithIgnoreAllowlist(true))
				requireAssertionFailure(t, err, tc.id, tc.reason)
			}
		})
	}

	t.Run("not JSON keeps the decoder's error", func(t *testing.T) {
		_, err := s.LoadTDF(bytes.NewReader(zipWithManifest(t, `{"payload":`)), WithIgnoreAllowlist(true))
		require.Error(t, err)
		var failure ErrAssertionFailure
		require.NotErrorAs(t, err, &failure)
	})

	t.Run("non-string id loads when verification is disabled", func(t *testing.T) {
		data := zipWithManifest(t, withAssertions(`[{"id":7,"type":"other","scope":"tdo","statement":{"value":"v"},"binding":"none"}]`))
		r, err := s.LoadTDF(bytes.NewReader(data), WithDisableAssertionVerification(true), WithIgnoreAllowlist(true))
		require.NoError(t, err)
		require.Len(t, r.Manifest().Assertions, 1)
		assert.Empty(t, r.Manifest().Assertions[0].ID)
	})
}

// fastestHash returns the quickest of a few ComputeAssertionHash runs on in,
// which keeps scheduler noise out of the timing comparisons below.
func fastestHash(t *testing.T, in []byte) time.Duration {
	t.Helper()
	best := time.Duration(math.MaxInt64)
	for range 3 {
		start := time.Now()
		_, err := ComputeAssertionHash(in)
		elapsed := time.Since(start)
		require.NoError(t, err)
		best = min(best, elapsed)
	}
	return best
}

// TestComputeAssertionHashScales checks that hashing an assertion costs time
// roughly linear in its size, whatever its shape: the input comes from the
// TDF, so a canonicalizer that sorts members quadratically or copies every
// subtree at every nesting level would let a large statement value stall the
// reader. Each case compares two inputs of the same size and requires the
// awkward one to be within a generous factor of the easy one.
func TestComputeAssertionHashScales(t *testing.T) {
	const (
		members = 40000
		factor  = 10
		slack   = 100 * time.Millisecond
	)
	object := func(descending bool) []byte {
		var b strings.Builder
		b.WriteString(`{"id":"a","statement":{"value":{`)
		for i := range members {
			k := i
			if descending {
				k = members - 1 - i
			}
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%08d":0`, k)
		}
		b.WriteString(`}}}`)
		return []byte(b.String())
	}
	payload := `"` + strings.Repeat("x", 400000) + `"`
	deep := `{"id":"a","v":` + strings.Repeat("[", 5000) + payload + strings.Repeat("]", 5000) + `}`
	shallow := `{"id":"a","v":[` + payload + `],"pad":"` + strings.Repeat("y", 9989) + `"}`
	require.Len(t, shallow, len(deep))

	for name, pair := range map[string][2][]byte{
		"members in ascending order": {object(true), object(false)},
		"deep nesting":               {[]byte(shallow), []byte(deep)},
	} {
		t.Run(name, func(t *testing.T) {
			easy, hard := fastestHash(t, pair[0]), fastestHash(t, pair[1])
			assert.Less(t, hard, factor*easy+slack, "easy input took %v, awkward input took %v", easy, hard)
		})
	}
}

func TestManifestUnmarshalAppliesSection3(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		id       string
		reason   AssertionFailureReason
	}{
		{"assertions and Assertions", `{"assertions":[{"id":"a"}],"Assertions":[{"id":"b"}]}`, "", AssertionReasonAmbiguousMember},
		{"duplicate assertions", `{"assertions":[{"id":"a"}],"assertions":[{"id":"b"}]}`, "", AssertionReasonDuplicateMember},
		{"id and ID", `{"assertions":[{"id":"a","ID":"b"}]}`, "a", AssertionReasonAmbiguousMember},
		{"invalid UTF-8", "{\"payload\":{\"mimeType\":\"\xff\"}}", "", AssertionReasonInvalidJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m Manifest
			requireAssertionFailure(t, json.Unmarshal([]byte(tc.manifest), &m), tc.id, tc.reason)
		})
	}

	var m Manifest
	require.NoError(t, json.Unmarshal([]byte(`{"assertions":[{"id":"a","ext":{"Assertions":1}}],"schemaVersion":"4.3.0"}`), &m))
	require.Len(t, m.Assertions, 1)
	assert.Equal(t, "a", m.Assertions[0].ID)
	assert.Equal(t, "4.3.0", m.TDFVersion)
}

func TestManifestWithByteOrderMarkIsRejected(t *testing.T) {
	requireAssertionFailure(t, parseManifestSection3([]byte("\ufeff"+minimalManifestJSON)), "", AssertionReasonInvalidJSON)
	_, err := newLoadTestSDK().LoadTDF(bytes.NewReader(zipWithManifest(t, "\ufeff"+minimalManifestJSON)), WithIgnoreAllowlist(true))
	require.Error(t, err)
}

func TestWriterRefusesAssertionsReadersReject(t *testing.T) {
	valid := AssertionConfig{ID: "a", Type: BaseAssertion, Scope: PayloadScope, Statement: Statement{Format: "text", Value: "v"}}
	key := bytes.Repeat([]byte{1}, 32)

	for name, tc := range map[string]struct {
		config AssertionConfig
		want   string
	}{
		"empty id":                   {AssertionConfig{Type: BaseAssertion, Scope: PayloadScope}, "id must be a nonempty string"},
		"noncharacter in the value":  {AssertionConfig{ID: "a", Statement: Statement{Value: "x\ufffey"}}, "invalid-json"},
		"noncharacter in the schema": {AssertionConfig{ID: "a", Statement: Statement{Schema: "\ufdd0"}}, "invalid-json"},
		"noncharacter in the id":     {AssertionConfig{ID: "\U0001FFFF"}, "invalid-json"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := signAssertions(bytes.Repeat([]byte{7}, 32), []AssertionConfig{valid, tc.config}, key, false)
			require.ErrorIs(t, err, ErrInvalidAssertion)
			require.NotErrorIs(t, err, ErrTampered)
			assert.NotContains(t, err.Error(), "tamper")
			assert.Contains(t, err.Error(), tc.want)

			err = WithAssertions(valid, tc.config)(&TDFConfig{})
			require.ErrorIs(t, err, ErrInvalidAssertion, "WithAssertions refuses it before any payload is written")
		})
	}

	require.NoError(t, WithAssertions(valid)(&TDFConfig{}))
	signed, err := signAssertions(bytes.Repeat([]byte{7}, 32), []AssertionConfig{valid}, key, false)
	require.NoError(t, err)
	require.Len(t, signed, 1)
}

func TestAssertionFailureRendersIDSafely(t *testing.T) {
	t.Run("escapes", func(t *testing.T) {
		id := "x, reason=signature-invalid\x1b[2K\n\\\u0085\t"
		err := assertionFailure(id, AssertionReasonBindingMismatch, "detail")
		var failure ErrAssertionFailure
		require.ErrorAs(t, err, &failure)
		assert.Equal(t, id, failure.ID, "the typed error keeps the exact id")
		msg := err.Error()
		assert.NotContains(t, msg, "\n")
		assert.NotContains(t, msg, "\x1b")
		assert.NotContains(t, msg, "\u0085")
		assert.Contains(t, msg, `id: x, reason=signature-invalid\u001b[2K\n\\\u0085\t, reason=binding-mismatch: detail`)
	})

	t.Run("long ids are cut", func(t *testing.T) {
		id := strings.Repeat("é", 300)
		msg := ErrAssertionFailure{ID: id, Reason: AssertionReasonInvalidID}.Error()
		assert.Contains(t, msg, "id: "+strings.Repeat("é", maxRenderedIDLength)+"…, reason=invalid-id")
		assert.NotContains(t, msg, strings.Repeat("é", maxRenderedIDLength+1))

		exact := strings.Repeat("é", maxRenderedIDLength)
		assert.Contains(t, ErrAssertionFailure{ID: exact}.Error(), "id: "+exact)
		assert.NotContains(t, ErrAssertionFailure{ID: exact}.Error(), "…")
	})
}

// TestLevelSpecsCoverManifestStructs checks that every json member of the
// structs the manifest decodes into is a modelled name at its level, so the
// case-variant table cannot drift from what the decoder matches.
func TestLevelSpecsCoverManifestStructs(t *testing.T) {
	var walk func(typ reflect.Type, level jsonLevel)
	walk = func(typ reflect.Type, level jsonLevel) {
		for i := range typ.NumField() {
			field := typ.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if !field.IsExported() || name == "-" {
				continue
			}
			require.NotEmpty(t, name, "%s.%s has no json name", typ.Name(), field.Name)
			assert.Contains(t, levelSpecs[level].names, name, "%s.%s at %q", typ.Name(), field.Name, levelSpecs[level].path)

			child := childLevel(level, name)
			ft := field.Type
			if ft.Kind() == reflect.Slice {
				ft = ft.Elem()
				child = levelSpecs[child].elements
			}
			if ft.Kind() == reflect.Struct {
				require.NotEqual(t, levelOther, child, "%s.%s holds a struct but leads to no level", typ.Name(), field.Name)
				walk(ft, child)
			}
		}
	}
	walk(reflect.TypeFor[Manifest](), levelManifest)
	// Members decoded outside the Manifest struct itself.
	walk(reflect.TypeFor[offSpecSpecVersion](), levelManifest)
	walk(reflect.TypeFor[PolicyBinding](), levelPolicyBinding)
	walk(reflect.TypeFor[Binding](), levelBinding)

	paths := map[string]bool{}
	for _, spec := range levelSpecs {
		if len(spec.names) > 0 {
			assert.False(t, paths[spec.path], "level path %q is used twice", spec.path)
			paths[spec.path] = true
		}
	}
}

func TestLoadTDFAcceptsLegacyIsStreamable(t *testing.T) {
	manifest := strings.Replace(minimalManifestJSON, `"encryptionInformation":{}`,
		`"encryptionInformation":{"method":{"algorithm":"AES-256-GCM","iv":"","IsStreamable":true}}`, 1)
	r, err := newLoadTestSDK().LoadTDF(bytes.NewReader(zipWithManifest(t, manifest)), WithIgnoreAllowlist(true))
	require.NoError(t, err)
	// encoding/json still matches the legacy spelling, as it always has; the
	// reader does not act on the field.
	assert.True(t, r.Manifest().Method.IsStreamable)
}
