// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	kGMACPayloadLength = 16
	kSplitKeyType      = "split"
	kPolicyBindingAlg  = "HS256"
)

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
	// IntegrityInformation IntegrityInformation `json:"integrityInformation"`
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
	Assertions            []Assertion `json:"assertions,omitempty"`
	TDFVersion            string      `json:"schemaVersion,omitempty"`
}

// manifestJSON mirrors Manifest but has no UnmarshalJSON method of its own, so
// the default decoder can be reused from Manifest.UnmarshalJSON without
// recursing back into it.
type manifestJSON Manifest

// offSpecSpecVersion locates tdf_spec_version, a deprecated name for the spec
// version field, at the manifest root and under payload.
//
// schemaVersion is the canonical name. tdf_spec_version is not a former
// spelling that was renamed on a schedule -- it entered some specification
// drafts and some older OpenTDF documentation in error, and writers built from
// those drafts emitted it. We read it so those files stay usable; we never
// write it.
//
// Both placements are probed because both occur in archival files, for two
// different reasons. The root is where the spec's own manifest.md has always
// documented the field, and where web-sdk both wrote it and still reads it
// (lib/tdf3/src/tdf.ts). Under payload is where revisions of the JSON schema
// declared it in error, which led at least one writer to emit the key there
// with a null value. The root is preferred when both carry a string.
//
// Values are typed as any rather than string because the key is known to
// appear with a null value, and because an off-spec type must not fail the
// whole decode -- reporting malformed manifests is schema validation's job,
// not the decoder's.
type offSpecSpecVersion struct {
	TDFSpecVersion any `json:"tdf_spec_version"`
	Payload        struct {
		TDFSpecVersion any `json:"tdf_spec_version"`
	} `json:"payload"`
}

// offSpecSpecVersionKey gates the second decode pass below. Almost every
// manifest without a schemaVersion has no off-spec copy either -- a pre-4.3.0
// container written by this SDK carries neither -- and a substring scan is far
// cheaper than tokenizing the document again to discover that.
//
// A key spelled with JSON escapes ("tdf_spec_version") would not match and
// its version would not be read. No writer emits that, and the result is
// exactly the pre-existing behavior of reporting no version, so the fallback
// simply does not fire rather than misreading anything.
var offSpecSpecVersionKey = []byte(`"tdf_spec_version"`)

// UnmarshalJSON decodes a TDF manifest, reading a deprecated tdf_spec_version
// as the spec version when the canonical schemaVersion is absent, so that
// files written against the deprecated name stay readable.
//
// Precedence is schemaVersion, then tdf_spec_version at the root, then
// tdf_spec_version under payload. Nothing is written back under the deprecated
// name -- re-marshalling a manifest always emits schemaVersion only, so a
// round trip normalizes the name rather than propagating it.
//
// The decoded version is metadata. It does not decide whether a container
// verifies: integrity digests are read off the file rather than off this
// field.
//
// This mirrors sdk.Manifest.UnmarshalJSON; the two manifest definitions are
// deliberate duplicates and must not drift.
func (m *Manifest) UnmarshalJSON(data []byte) error {
	var base manifestJSON
	if err := json.Unmarshal(data, &base); err != nil {
		return err
	}
	*m = Manifest(base)

	if m.TDFVersion != "" || !bytes.Contains(data, offSpecSpecVersionKey) {
		return nil
	}

	var offSpec offSpecSpecVersion
	if err := json.Unmarshal(data, &offSpec); err != nil {
		return err
	}
	for _, candidate := range []any{offSpec.TDFSpecVersion, offSpec.Payload.TDFSpecVersion} {
		if v, ok := candidate.(string); ok && v != "" {
			m.TDFVersion = v
			return nil
		}
	}
	return nil
}

type PolicyAttribute struct {
	Attribute   string `json:"attribute"`
	DisplayName string `json:"displayName"`
	IsDefault   bool   `json:"isDefault"`
	PubKey      string `json:"pubKey"`
	KasURL      string `json:"kasURL"`
}

type Policy struct {
	UUID string     `json:"uuid"`
	Body PolicyBody `json:"body"`
}

type PolicyBody struct {
	DataAttributes []PolicyAttribute `json:"dataAttributes"`
	Dissem         []string          `json:"dissem"`
}

type Segment struct {
	Hash          string `json:"hash"`
	Size          int64  `json:"segmentSize"`
	EncryptedSize int64  `json:"encryptedSegmentSize"`
}
type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
}
type EncryptedMetadata struct {
	Cipher string `json:"ciphertext"`
	Iv     string `json:"iv"`
}

var (
	// ErrUnsupportedRootIntegrityAlgorithm rejects any root signature
	// algorithm other than HS256.
	ErrUnsupportedRootIntegrityAlgorithm = errors.New("tdf: unsupported root integrity algorithm")
	// ErrUnsupportedSegmentIntegrityAlgorithm rejects a segment algorithm that
	// is neither HS256 nor GMAC. SegmentIntegrityAlg is int-backed, so this
	// catches an out-of-range value before it reaches a manifest.
	ErrUnsupportedSegmentIntegrityAlgorithm = errors.New("tdf: unsupported segment integrity algorithm")
)

// None of these helpers take the hex-encoding flag the stable SDK carries for
// 4.2.2 files: this package only ever writes current-spec TDFs.

// hmacIntegrity is the HMAC-SHA256 primitive both signature paths share. It
// takes no algorithm argument, so it cannot be pointed at the wrong branch.
func hmacIntegrity(data, secret []byte) string {
	return string(ocrypto.CalculateSHA256Hmac(secret, data))
}

// readAEADTag returns the trailing AES-GCM tag of a segment's ciphertext.
//
// This is only an authenticator because the cipher computed that tag over
// exactly these bytes. Applied to anything the AEAD did not produce it
// authenticates nothing: it just returns a copy of the input's own last 16
// bytes. Hence unexported, and reachable only through segmentIntegrity.
func readAEADTag(ciphertext []byte) (string, error) {
	if kGMACPayloadLength > len(ciphertext) {
		return "", errors.New("fail to create gmac signature")
	}
	return string(ciphertext[len(ciphertext)-kGMACPayloadLength:]), nil
}

// segmentIntegrity computes the integrity value recorded in a segment's
// manifest entry. Both algorithms are legitimate here: the input is data the
// cipher produced.
func segmentIntegrity(ciphertext, key []byte, alg SegmentIntegrityAlg) (string, error) {
	switch alg {
	case SegmentHS256:
		return hmacIntegrity(ciphertext, key), nil
	case SegmentGMAC:
		return readAEADTag(ciphertext)
	}
	return "", fmt.Errorf("%w: %s", ErrUnsupportedSegmentIntegrityAlgorithm, alg)
}

// rootIntegrity computes the root signature over the aggregate hash: the
// concatenation of every segment's hash, in manifest order.
//
// HS256 only. AES-GCM never processed the aggregate hash, so there is no tag to
// extract and no keyless construction that could authenticate it.
// RootIntegrityAlg has no other named value, but it is int-backed, so the check
// still has to run.
func rootIntegrity(aggregateHash, key []byte, alg RootIntegrityAlg) (string, error) {
	if alg != RootHS256 {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedRootIntegrityAlgorithm, alg)
	}
	return hmacIntegrity(aggregateHash, key), nil
}
