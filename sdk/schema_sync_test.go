package sdk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Three copies of the manifest schema exist and have drifted apart before:
// this SDK's strict copy, this SDK's lax copy, and the normative one in
// opentdf/spec. Drift is not a cosmetic problem -- xtest once validated
// against a copy with no hybrid-wrapped key access type and no HS256
// constraint on the root signature, so CI rejected manifests the platform
// accepts and accepted a GMAC root it rejects. These tests pin the copies
// together so that can only happen deliberately.

// prose lists keywords that carry no constraint. Copies may word them
// differently -- each is written for its own audience -- and $id necessarily
// differs because the copies are not the same document.
var prose = map[string]bool{"description": true, "title": true, "$id": true}

// flattenSchema reduces a schema to the constraints it imposes, keyed by
// path, so two copies can be compared without regard to key order, whitespace
// or prose. Leaf arrays (enum, required, type unions) are sorted, since JSON
// Schema gives their order no meaning.
func flattenSchema(t *testing.T, node any, path string, out map[string]string) {
	t.Helper()

	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if prose[k] {
				continue
			}
			flattenSchema(t, v, path+"/"+k, out)
		}
	case []any:
		leaf := true
		for _, v := range n {
			switch v.(type) {
			case map[string]any, []any:
				leaf = false
			}
		}
		if leaf {
			vals := make([]string, 0, len(n))
			for _, v := range n {
				vals = append(vals, fmt.Sprint(v))
			}
			sort.Strings(vals)
			out[path] = fmt.Sprint(vals)
			return
		}
		for i, v := range n {
			flattenSchema(t, v, fmt.Sprintf("%s/%d", path, i), out)
		}
	default:
		out[path] = fmt.Sprint(node)
	}
}

func flattenSchemaFile(t *testing.T, data []byte) map[string]string {
	t.Helper()

	var doc any
	require.NoError(t, json.Unmarshal(data, &doc))

	out := map[string]string{}
	flattenSchema(t, doc, "", out)
	return out
}

// diffSchemas returns every path where a and b disagree, as
// "path: a -> b". An absent path reads as "<absent>".
func diffSchemas(a, b map[string]string) map[string]string {
	const absent = "<absent>"
	diff := map[string]string{}
	for k, av := range a {
		if bv, ok := b[k]; !ok || bv != av {
			if !ok {
				bv = absent
			}
			diff[k] = av + " -> " + bv
		}
	}
	for k, bv := range b {
		if _, ok := a[k]; !ok {
			diff[k] = absent + " -> " + bv
		}
	}
	return diff
}

// laxRelaxations is the complete set of constraints Lax drops relative to
// Strict, each with the reason it is dropped. Lax backs IsValidTdf, which
// answers "is this a TDF at all" for callers that have not decrypted yet, so
// it tolerates the shapes real writers emit; Strict is the conformance
// statement. Any other difference is drift, and this test fails on it.
var laxRelaxations = map[string]string{
	// Nulls real writers emit. Reporting them is schema validation's job at
	// Strict; at Lax they must not stop a readable file from being read.
	"/properties/payload/properties/tdf_spec_version/type":                                            "string -> [null string]",
	"/properties/assertions/items/properties/appliesToState/type":                                     "string -> [null string]",
	"/properties/encryptionInformation/properties/keyAccess/items/properties/sid/type":                "string -> [null string]",
	"/properties/encryptionInformation/properties/keyAccess/items/properties/encryptedMetadata/type":  "string -> [null string]",
	"/properties/encryptionInformation/properties/keyAccess/items/properties/ephemeralPublicKey/type": "string -> [null string]",

	// The root algorithm is enforced by validateRootSignature at every
	// validation intensity. Rejecting it here too would report
	// ErrInvalidPerSchema instead of ErrRootSignatureFailure, and would let a
	// schema setting mask the integrity check.
	"/properties/encryptionInformation/properties/integrityInformation/properties/rootSignature/properties/alg/enum": "[HS256] -> <absent>",
}

// specDivergences is the complete set of constraints on which this SDK's
// strict schema differs from the normative copy in opentdf/spec, each with the
// reason it has not been carried over yet.
//
// The list is meant to shrink. It exists so that a divergence is a recorded
// decision rather than something discovered when a TDF one implementation
// writes is rejected by another -- which is how the last round of drift came
// to light.
var specDivergences = map[string]string{
	// The spec schema declares the spec version at the manifest root, under
	// both its canonical and deprecated names, and permits the null that some
	// writers emit for the payload copy. The reader here already accepts all
	// of that (see Manifest.UnmarshalJSON); carrying it into the bundled
	// schemas widens what IsValidTdf(Strict) accepts, so it is being taken
	// separately rather than folded into a reader change.
	"/properties/schemaVersion/type":                       "string -> <absent>",
	"/properties/tdf_spec_version/type":                    "string -> <absent>",
	"/properties/payload/properties/tdf_spec_version/type": "[null string] -> string",

	// Assertion statements carry a schema identifier -- every SDK writes one
	// and the Go Assertion type has the field -- but only the spec copy
	// declares it. Undeclared is not rejected, since neither copy sets
	// additionalProperties, so this is a documentation gap rather than a
	// behavioral one.
	"/properties/assertions/items/properties/statement/properties/schema/type": "string -> <absent>",
}

// TestSchemaLaxRelaxesStrictDeliberately pins the lax schema to the strict one.
// Lax exists to accept nulls real writers emit, not to be a second schema with
// a life of its own: a constraint added to one copy and forgotten in the other
// shows up here.
func TestSchemaLaxRelaxesStrictDeliberately(t *testing.T) {
	strict := flattenSchemaFile(t, manifestStrictSchema)
	lax := flattenSchemaFile(t, manifestLaxSchema)

	assert.Equal(t, laxRelaxations, diffSchemas(strict, lax),
		"lax and strict differ somewhere other than the documented relaxations; "+
			"either make the copies agree or add the relaxation to laxRelaxations with its reason")
}

// TestSchemaMatchesSpec pins the strict schema to the normative copy in
// opentdf/spec, which is a separate repository. Prose is excluded -- each copy
// is written for its own readers -- so what is compared is the constraints.
//
// Skipped unless OPENTDF_SPEC_DIR points at a spec checkout, which the
// schema-sync workflow sets. Running it locally is the same command with the
// variable set.
func TestSchemaMatchesSpec(t *testing.T) {
	specDir := os.Getenv("OPENTDF_SPEC_DIR")
	if specDir == "" {
		t.Skip("OPENTDF_SPEC_DIR is unset; set it to an opentdf/spec checkout to compare against the normative schema")
	}

	specPath := filepath.Join(specDir, "schema", "OpenTDF", "json-schema", "schema.json")
	data, err := os.ReadFile(specPath)
	require.NoError(t, err, "reading the normative schema at %s", specPath)

	assert.Equal(t, specDivergences, diffSchemas(flattenSchemaFile(t, data), flattenSchemaFile(t, manifestStrictSchema)),
		"sdk/schema/manifest.schema.json diverges from the normative schema somewhere other than the "+
			"recorded divergences; either bring the copies together or add the divergence to "+
			"specDivergences with the reason it stands")
}
