// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
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

// ErrUnsupportedRootIntegrityAlgorithm rejects any root signature algorithm
// other than HS256. See the stable SDK's error of the same name for the full
// rationale: the root signature covers the aggregate hash, which AES-GCM never
// processed, so there is no tag to read back out and a "GMAC" root
// authenticates nothing.
var ErrUnsupportedRootIntegrityAlgorithm = errors.New("tdf: unsupported root integrity algorithm")

// hmacIntegrity computes an HMAC-SHA256 over data, keyed by the DEK.
//
// Unlike the stable SDK's namesake there is no legacy hex-encoding branch: this
// package only ever writes current-format TDFs, so the digest goes straight to
// the caller's base64.
func hmacIntegrity(data, key []byte) string {
	return string(ocrypto.CalculateSHA256Hmac(key, data))
}

// readAEADTag returns the trailing authentication tag of an AES-GCM ciphertext.
//
// PRECONDITION: ciphertext must be exactly the bytes AES-GCM sealed under the
// DEK. Only then are the trailing kGMACPayloadLength bytes the tag the cipher
// already computed over them; over anything else the same rule just copies the
// input's own last 16 bytes and authenticates nothing. Reachable only from
// segmentIntegrity, whose argument is by construction a segment ciphertext.
func readAEADTag(ciphertext []byte) (string, error) {
	if kGMACPayloadLength > len(ciphertext) {
		return "", errors.New("fail to create gmac signature")
	}

	return string(ciphertext[len(ciphertext)-kGMACPayloadLength:]), nil
}

// segmentIntegrity computes a segment's integrity value over its AES-GCM
// ciphertext. Both algorithms are legitimate here: GMAC reads out the AEAD tag
// covering exactly these bytes, HS256 recomputes an HMAC over them.
func segmentIntegrity(ciphertext, key []byte, alg IntegrityAlgorithm) (string, error) {
	if alg == HS256 {
		return hmacIntegrity(ciphertext, key), nil
	}
	return readAEADTag(ciphertext)
}

// rootIntegrity computes the root signature over the aggregate hash. HS256
// only; see ErrUnsupportedRootIntegrityAlgorithm.
func rootIntegrity(aggregateHash, key []byte, alg IntegrityAlgorithm) (string, error) {
	if alg != HS256 {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedRootIntegrityAlgorithm, alg)
	}
	return hmacIntegrity(aggregateHash, key), nil
}
