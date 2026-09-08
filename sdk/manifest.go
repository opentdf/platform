package sdk

import "fmt"

// Segment describes one chunk of the payload.
//
// Size and EncryptedSize are optional in the wire format:
// manifest.schema.json marks segmentSizeDefault and
// encryptedSegmentSizeDefault required on integrityInformation but declares
// no required list on segments/items, so a writer may omit a per-segment
// size whenever it equals the manifest-level default. web-sdk does exactly
// that for every full-sized segment. An omitted key unmarshals to 0, which
// is not a legal segment size, so 0 means "absent, use the default" -- see
// IntegrityInformation.resolveSegmentSizes.
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
// substituting the manifest-level defaults for values the writer omitted.
//
// Both must come out positive. A segment of length zero is not something a
// writer can legitimately describe, and letting one through makes the
// caller's `len(readBuf) != encryptedSize` check pass vacuously -- the read
// then fails several frames later inside the GMAC signature calculation,
// where the message says nothing about the manifest.
func (i IntegrityInformation) resolveSegmentSizes(seg Segment) (int64, int64, error) {
	size := seg.Size
	if size == 0 {
		size = i.DefaultSegmentSize
	}

	encryptedSize := seg.EncryptedSize
	if encryptedSize == 0 {
		encryptedSize = i.DefaultEncryptedSegSize
	}

	if size <= 0 || encryptedSize <= 0 {
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
