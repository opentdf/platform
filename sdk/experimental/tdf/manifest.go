// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk"
)

// These are unchanged copies of what sdk defines unexported. They stay
// here only while this package still builds manifests itself; the
// delegation that removes their last callers is a follow-up.
const (
	kGMACPayloadLength = 16
	kKeySize           = 32
	kSplitKeyType      = "split"
	kPolicyBindingAlg  = "HS256"
)

// The manifest types below are aliases onto their
// [github.com/opentdf/platform/sdk] counterparts, which own the definitions.
// They are kept here so that existing importers of this experimental package
// continue to compile unchanged, and so a manifest produced here can be
// handed to the stable SDK without conversion. Prefer the sdk-scoped names in
// new code.
type (
	// RootSignature is the signature over the concatenated segment hashes.
	//
	// See [sdk.RootSignature].
	RootSignature = sdk.RootSignature

	// IntegrityInformation describes segment layout and the hashes that
	// protect the payload.
	//
	// See [sdk.IntegrityInformation].
	IntegrityInformation = sdk.IntegrityInformation

	// KeyAccess is one wrapped key share addressed to a single KAS.
	//
	// See [sdk.KeyAccess].
	KeyAccess = sdk.KeyAccess

	// Method describes the payload encryption algorithm and IV.
	//
	// See [sdk.Method].
	Method = sdk.Method

	// Payload describes the encrypted payload entry in the archive.
	//
	// See [sdk.Payload].
	Payload = sdk.Payload

	// EncryptionInformation carries the policy, key access objects, and
	// integrity information for a TDF.
	//
	// See [sdk.EncryptionInformation].
	EncryptionInformation = sdk.EncryptionInformation

	// Manifest is the TDF manifest written to manifest.json.
	//
	// See [sdk.Manifest].
	Manifest = sdk.Manifest

	// Segment is one encrypted chunk of the payload plus its integrity hash.
	//
	// See [sdk.Segment].
	Segment = sdk.Segment

	// PolicyBinding is the HMAC binding a key share to the policy.
	//
	// See [sdk.PolicyBinding].
	PolicyBinding = sdk.PolicyBinding

	// EncryptedMetadata is the AES-GCM envelope for a key access object's
	// opaque metadata.
	//
	// See [sdk.EncryptedMetadata].
	EncryptedMetadata = sdk.EncryptedMetadata
)

// Policy, PolicyBody, and PolicyAttribute are deliberately not aliased onto
// [sdk.PolicyObject]: the sdk type declares Body as an anonymous struct over
// an unexported element type, so it has no nameable equivalent for these
// three. Exporting those in sdk first would make the alias possible.

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
