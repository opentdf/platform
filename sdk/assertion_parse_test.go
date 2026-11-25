package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

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
