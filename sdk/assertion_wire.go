package sdk

import (
	"bytes"

	"github.com/gowebpki/jcs"
	"github.com/opentdf/platform/lib/ocrypto"
)

// assertionWireCapture keeps the assertion's members, the members of its
// statement and binding objects, and those members' decoded values.
const assertionWireCapture = 3

// assertionWire is one assertion object exactly as received, parsed under
// spec Section 3. Verification reads modelled members from it by exact name,
// never through the case-insensitive struct decoder.
type assertionWire struct {
	raw  []byte
	root jsonNode
}

// parseAssertionWire parses the raw JSON of one assertion object, rejecting
// duplicate members, case variants in the assertion, statement and binding
// objects, and I-JSON violations.
func parseAssertionWire(raw []byte) (*assertionWire, error) {
	root, err := parseStrictJSON(raw, levelAssertion, assertionWireCapture)
	if err != nil {
		return nil, section3Error("", err)
	}
	return &assertionWire{raw: raw, root: root}, nil
}

// exactID returns the assertion's "id" when it is a nonempty JSON string, as
// spec Section 3.3 requires. The decoded string is compared exactly: no
// trimming, case folding, or normalization.
func (w *assertionWire) exactID() (string, bool) {
	if w.root.kind != jsonObject {
		return "", false
	}
	v, ok := w.root.member("id")
	if !ok || v.kind != jsonString || v.str == "" || v.strProblem != "" {
		return "", false
	}
	return v.str, true
}

// knownID is exactID for error messages: the id if there is a valid one,
// and empty otherwise.
func (w *assertionWire) knownID() string {
	id, _ := w.exactID()
	return id
}

// hash computes assertionHash under spec Section 4: the lowercase hex
// SHA-256 of the RFC 8785 canonical form of the object minus only its
// top-level "binding" member. Every other member is kept as received,
// including members this SDK does not model.
func (w *assertionWire) hash() (string, error) {
	if w.root.kind != jsonObject {
		return "", assertionFailure("", AssertionReasonInvalidJSON, "assertion is not a JSON object")
	}
	var b bytes.Buffer
	b.Grow(len(w.raw))
	b.WriteByte('{')
	first := true
	for _, m := range w.root.members {
		if m.name == bindingMember {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.Write(w.raw[m.start:m.value.end])
	}
	b.WriteByte('}')
	canonical, err := jcs.Transform(b.Bytes())
	if err != nil {
		return "", assertionFailureCause(w.knownID(), AssertionReasonInvalidJSON, "canonicalizing the assertion", err)
	}
	return string(ocrypto.SHA256AsHex(canonical)), nil
}

// ComputeAssertionHash returns the assertionHash of one assertion, given the
// raw JSON text of its wire object as it appears in a manifest.
//
// It applies the parsing rules of the ZTDF assertions specification
// (Section 3): duplicate member names, case variants in the assertion,
// statement and binding objects (a variant of a modelled name such as "ID",
// or two names that differ only in case), and non-I-JSON content are
// rejected. It then removes only the top-level "binding" member,
// canonicalizes the rest with RFC 8785 (JCS), and returns the lowercase hex
// SHA-256 of the result. Members the SDK does not model are hashed too, and
// a statement value keeps the JSON type it was received with.
//
// Use it to check an assertion outside the SDK's reader: compare the result
// with the binding's assertionHash claim only after verifying the binding's
// signature with a key you trust. Errors are ErrAssertionFailure values.
func ComputeAssertionHash(wire []byte) (string, error) {
	w, err := parseAssertionWire(wire)
	if err != nil {
		return "", err
	}
	return w.hash()
}
