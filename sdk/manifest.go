package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Segment describes one chunk of the payload.
//
// Size and EncryptedSize are optional in the wire format: a writer may omit
// either key whenever its value equals the corresponding manifest-level
// default. Since JSON can't distinguish an omitted key from an explicit 0,
// a zero EncryptedSize always means "omitted" -- ciphertext is never
// legitimately zero bytes -- but a zero Size is ambiguous; see
// resolveSegmentSizes for how it's disambiguated.
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

// resolveSegmentSizes returns the plaintext and ciphertext sizes of seg in
// bytes, substituting the manifest-level default for whichever field the
// writer omitted, and validates that the resolved pair is internally
// consistent.
//
// EncryptedSize is never ambiguous on its own: ciphertext is never
// legitimately zero-length (there is always at least a nonce and a tag), so
// a raw 0 always means the key was left out because it equals
// DefaultEncryptedSegSize.
//
// Size is ambiguous on its own: web-sdk, for example, omits Size and
// EncryptedSize independently of each other, each time its own value equals
// the manifest-level default -- so a zero Size doesn't necessarily mean
// EncryptedSize was omitted too. Disambiguate by comparing the resolved
// EncryptedSize against its own default instead.
//
// AES-GCM frames every segment with a fixed-size nonce and tag, so the
// plaintext size is pinned by the ciphertext size regardless of which
// fields the manifest declared explicitly. A resolved pair that disagrees
// with that framing is rejected here -- whether the inconsistency came from
// the per-segment fields or the manifest-level defaults -- rather than left
// for a caller to discover downstream.
func (i IntegrityInformation) resolveSegmentSizes(seg Segment) (int64, int64, error) {
	encryptedSize := seg.EncryptedSize
	if encryptedSize == 0 {
		encryptedSize = i.DefaultEncryptedSegSize
	}

	size := seg.Size
	if size == 0 && encryptedSize == i.DefaultEncryptedSegSize {
		size = i.DefaultSegmentSize
	}

	if size < 0 || encryptedSize <= 0 {
		return 0, 0, fmt.Errorf("%w: segmentSize=%d encryptedSegmentSize=%d", ErrSegSizeUnresolved, size, encryptedSize)
	}

	if encryptedSize < gcmIvSize+aesBlockSize || size != encryptedSize-(gcmIvSize+aesBlockSize) {
		return 0, 0, fmt.Errorf("%w: segment declares size %d with encrypted size %d", ErrSegSizeMismatch, size, encryptedSize)
	}

	return size, encryptedSize, nil
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

type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
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

// offSpecSpecVersion locates tdf_spec_version under payload, an off-spec name
// for the spec version field.
//
// schemaVersion is and has always been the correct name. tdf_spec_version is
// not a former spelling that was later renamed -- it is an error that leaked
// into some specification drafts and some older OpenTDF documentation, and into
// the writers built from them. We read it so those files remain usable; we
// never write it, and it is not on a deprecation path because it was never
// correct to begin with.
//
// Only payload is probed, because that is the one placement with a definition
// to point at: the schemas bundled with this SDK
// (sdk/schema/manifest*.schema.json) declare tdf_spec_version under payload and
// nowhere else. A copy at the manifest root is not read.
//
// The value is typed as any rather than string because the lax schema permits
// tdf_spec_version to be null, and an off-spec type must not fail the whole
// decode -- reporting malformed manifests is schema validation's job, not the
// decoder's.
type offSpecSpecVersion struct {
	Payload struct {
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

// UnmarshalJSON decodes a TDF manifest, reading an off-spec tdf_spec_version as
// the spec version when the correct schemaVersion is absent, so that files
// written against the erroneous name stay readable.
//
// schemaVersion always wins when both names are present. Nothing is written
// back under the off-spec name -- re-marshalling a manifest always emits
// schemaVersion only.
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
	if v, ok := offSpec.Payload.TDFSpecVersion.(string); ok {
		m.TDFVersion = v
	}
	return nil
}

type attributeObject struct {
	Attribute   string `json:"attribute"`
	DisplayName string `json:"displayName"`
	IsDefault   bool   `json:"isDefault"`
	PubKey      string `json:"pubKey"`
	KasURL      string `json:"kasURL"`
}

type PolicyObject struct {
	UUID string `json:"uuid"`
	Body struct {
		DataAttributes []attributeObject `json:"dataAttributes"`
		Dissem         []string          `json:"dissem"`
	} `json:"body"`
}

type EncryptedMetadata struct {
	Cipher string `json:"ciphertext"`
	Iv     string `json:"iv"`
}
