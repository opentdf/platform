package sdk

import "fmt"

// Segment describes one chunk of the payload.
//
// Size and EncryptedSize are optional in the wire format:
// manifest.schema.json marks segmentSizeDefault and
// encryptedSegmentSizeDefault required on integrityInformation but declares
// no required list on segments/items, so a writer may omit a per-segment
// size whenever it equals the manifest-level default. web-sdk does exactly
// that -- deciding whether to omit Size and EncryptedSize independently of
// each other, not as a pair. JSON can't distinguish an omitted key from an
// explicit 0, though, and a segment legitimately can hold zero plaintext
// bytes -- go-sdk's own CreateTDF writes segmentSize: 0 for the sole
// segment of an empty-payload TDF. See IntegrityInformation.
// resolveSegmentSizes for how the two are told apart.
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

// resolveSegmentSizes returns the plaintext and ciphertext sizes of seg,
// substituting the manifest-level default for whichever field the writer
// omitted.
//
// EncryptedSize is never ambiguous on its own: ciphertext is never
// legitimately zero-length (there is always at least a nonce and a tag), so
// a raw 0 always means the key was left out because it equals
// DefaultEncryptedSegSize.
//
// Size is ambiguous on its own -- web-sdk decides whether to omit Size and
// EncryptedSize independently (two separate equals-the-default checks, not
// one joint check), and JSON can't tell an omitted key from an explicit 0.
// But the per-segment cipher overhead is constant across every segment in
// one manifest, so whether the resolved EncryptedSize equals the default
// tells us, without knowing that overhead, whether the plaintext size does
// too: if it does, a stated Size of 0 was omitted and really is
// DefaultSegmentSize; if it doesn't, the writer would not have omitted a
// Size equal to the default, so 0 is literal -- a genuinely empty segment,
// which go-sdk's own CreateTDF produces for an empty-payload TDF.
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
