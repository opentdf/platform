package sdk

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The shared conformance vectors (DSPX-5520) are maintained in opentdf/tests
// as xtest/vectors/assertions-phase0.json. This file is a byte-identical copy;
// update it by copying, never by editing.
var assertionVectorsPath = filepath.Join("testdata", "assertion-vectors-phase0.json")

const assertionVectorsFormat = "opentdf-assertion-vectors/1"

type assertionVectorFile struct {
	Format                string                        `json:"format"`
	Source                string                        `json:"source"`
	ModelledNames         map[string][]string           `json:"modelledNames"`
	CaseVariantExceptions map[string][]string           `json:"caseVariantExceptions"`
	Keys                  map[string]assertionVectorKey `json:"keys"`
	Vectors               []assertionVector             `json:"vectors"`
}

type assertionVectorKey struct {
	Alg          string `json:"alg"`
	PublicKeyPEM string `json:"publicKeyPem"`
	SecretBase64 string `json:"secretBase64"`
}

type assertionVector struct {
	Name                string  `json:"name"`
	Kind                string  `json:"kind"`
	Status              string  `json:"status"`
	Note                string  `json:"note"`
	Input               *string `json:"input"`
	InputBase64         *string `json:"inputBase64"`
	SelectedKey         string  `json:"selectedKey"`
	KeySource           string  `json:"keySource"`
	AggregateHashBase64 string  `json:"aggregateHashBase64"`
	Legacy              bool    `json:"legacy"`
	Expect              struct {
		AssertionHash string `json:"assertionHash"`
		Reason        string `json:"reason"`
		OK            *bool  `json:"ok"`
		BindingForm   string `json:"bindingForm"`
	} `json:"expect"`
}

// vectorOutcome is what the SDK produced for one vector, in the vocabulary of
// its expect object.
type vectorOutcome struct {
	assertionHash string
	bindingForm   string
	ok            bool
	reason        string
}

func (o vectorOutcome) String() string {
	switch {
	case o.reason != "":
		return "reason " + o.reason
	case o.assertionHash != "":
		return "assertionHash " + o.assertionHash
	case o.bindingForm != "":
		return "bindingForm " + o.bindingForm
	default:
		return fmt.Sprintf("ok %v", o.ok)
	}
}

func outcomeOf(err error) vectorOutcome {
	if err == nil {
		return vectorOutcome{ok: true}
	}
	var failure ErrAssertionFailure
	if errors.As(err, &failure) {
		return vectorOutcome{reason: string(failure.Reason)}
	}
	return vectorOutcome{reason: "untyped error: " + err.Error()}
}

func (v assertionVector) input(t *testing.T) []byte {
	t.Helper()
	switch {
	case v.Input != nil && v.InputBase64 == nil:
		return []byte(*v.Input)
	case v.InputBase64 != nil && v.Input == nil:
		b, err := base64.StdEncoding.DecodeString(*v.InputBase64)
		require.NoError(t, err, "inputBase64")
		return b
	default:
		t.Fatalf("vector %s must have exactly one of input and inputBase64", v.Name)
		return nil
	}
}

// assertionKey returns the key as a caller would configure it: the alg as
// given, with key material decoded from whichever member holds it. Some
// vector keys are deliberately unusable; preparing them must fail.
func (k assertionVectorKey) assertionKey(t *testing.T) AssertionKey {
	t.Helper()
	var material any
	switch {
	case k.PublicKeyPEM != "" && k.SecretBase64 == "":
		block, _ := pem.Decode([]byte(k.PublicKeyPEM))
		require.NotNil(t, block, "publicKeyPem")
		var err error
		if block.Type == "RSA PUBLIC KEY" {
			material, err = x509.ParsePKCS1PublicKey(block.Bytes)
		} else {
			material, err = x509.ParsePKIXPublicKey(block.Bytes)
		}
		require.NoError(t, err, "publicKeyPem")
	case k.SecretBase64 != "" && k.PublicKeyPEM == "":
		secret, err := base64.StdEncoding.DecodeString(k.SecretBase64)
		require.NoError(t, err, "secretBase64")
		material = secret
	default:
		t.Fatal("a key needs exactly one of publicKeyPem and secretBase64")
	}
	return AssertionKey{Alg: AssertionKeyAlg(k.Alg), Key: material}
}

// run applies the harness for the vector's kind, as the vector format defines it.
func (v assertionVector) run(t *testing.T, keys map[string]assertionVectorKey) vectorOutcome {
	t.Helper()
	input := v.input(t)
	switch v.Kind {
	case "manifest":
		return outcomeOf(parseManifestSection3(input))

	case "assertion":
		w, err := parseAssertionWire(input)
		if err != nil {
			return outcomeOf(err)
		}
		if _, ok := w.exactID(); !ok {
			return vectorOutcome{reason: string(AssertionReasonInvalidID)}
		}
		h, err := ComputeAssertionHash(input)
		if err != nil {
			return outcomeOf(err)
		}
		return vectorOutcome{assertionHash: h}

	case "binding":
		w, err := parseAssertionWire(input)
		if err != nil {
			return outcomeOf(err)
		}
		if _, err := w.jwsBinding(w.knownID()); err != nil {
			return outcomeOf(err)
		}
		return vectorOutcome{bindingForm: "jws"}

	case "verify":
		key, ok := keys[v.SelectedKey]
		require.True(t, ok, "selectedKey %q is not in keys", v.SelectedKey)
		require.Contains(t, []string{"configured", "payload"}, v.KeySource, "keySource")
		aggregate, err := base64.StdEncoding.DecodeString(v.AggregateHashBase64)
		require.NoError(t, err, "aggregateHashBase64")
		w, err := parseAssertionWire(input)
		if err != nil {
			return outcomeOf(err)
		}
		id := w.knownID()
		prepare := newConfiguredVerifier
		if v.KeySource == "payload" {
			prepare = newAssertionVerifier
		}
		verifier, err := prepare(key.assertionKey(t))
		if err != nil {
			return vectorOutcome{reason: string(AssertionReasonConfigurationError)}
		}
		return outcomeOf(w.verify(id, verifier, aggregate, v.Legacy))

	default:
		t.Fatalf("vector %s has unknown kind %q", v.Name, v.Kind)
		return vectorOutcome{}
	}
}

func (v assertionVector) want(t *testing.T) vectorOutcome {
	t.Helper()
	e := v.Expect
	switch {
	case e.Reason != "":
		return vectorOutcome{reason: e.Reason}
	case e.AssertionHash != "":
		require.Equal(t, "assertion", v.Kind, "assertionHash expected from a non-assertion vector")
		return vectorOutcome{assertionHash: e.AssertionHash}
	case e.BindingForm != "":
		require.Equal(t, "binding", v.Kind, "bindingForm expected from a non-binding vector")
		return vectorOutcome{bindingForm: e.BindingForm}
	case e.OK != nil && *e.OK:
		return vectorOutcome{ok: true}
	default:
		t.Fatalf("vector %s has no usable expect", v.Name)
		return vectorOutcome{}
	}
}

func TestAssertionConformanceVectors(t *testing.T) {
	data, err := os.ReadFile(assertionVectorsPath)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not vendored yet", assertionVectorsPath)
	}
	require.NoError(t, err)

	var file assertionVectorFile
	require.NoError(t, json.Unmarshal(data, &file))
	require.Equal(t, assertionVectorsFormat, file.Format)
	require.NotEmpty(t, file.Vectors)

	t.Run("modelled names match the shared table", func(t *testing.T) {
		names, exceptions := map[string][]string{}, map[string][]string{}
		for _, spec := range levelSpecs {
			if len(spec.names) > 0 {
				names[spec.path] = spec.names
			}
			if len(spec.exceptions) > 0 {
				exceptions[spec.path] = spec.exceptions
			}
		}
		require.NotEmpty(t, file.ModelledNames)
		assert.ElementsMatch(t, slices.Collect(maps.Keys(file.ModelledNames)), slices.Collect(maps.Keys(names)), "levels")
		for path, want := range file.ModelledNames {
			assert.ElementsMatch(t, want, names[path], "names at %q", path)
		}
		assert.Equal(t, file.CaseVariantExceptions, exceptions)
	})

	seen := map[string]bool{}
	for _, v := range file.Vectors {
		require.NotEmpty(t, v.Name)
		require.False(t, seen[v.Name], "duplicate vector name %q", v.Name)
		seen[v.Name] = true

		t.Run(v.Name, func(t *testing.T) {
			require.Contains(t, []string{"required", "proposed"}, v.Status, "status")
			got := v.run(t, file.Keys)
			want := v.want(t)
			if v.Status == "proposed" {
				if got != want {
					t.Logf("proposed vector %s: got %v, want %v (%s)", v.Name, got, want, v.Note)
				}
				return
			}
			require.Equal(t, want.String(), got.String(), v.Note)
		})
	}
}
