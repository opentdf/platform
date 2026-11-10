// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"github.com/opentdf/platform/sdk"
)

// Aliases onto [github.com/opentdf/platform/sdk], which owns the definitions.
// See the package doc for why.
type (
	// RootSignature is the HMAC-SHA256 over the concatenated segment hashes,
	// in manifest order, keyed by the payload key. HS256 is the only accepted
	// algorithm.
	//
	// See [sdk.RootSignature].
	RootSignature = sdk.RootSignature

	// IntegrityInformation describes segment layout and the hashes that
	// protect the payload.
	//
	// See [sdk.IntegrityInformation].
	IntegrityInformation = sdk.IntegrityInformation

	// KeyAccess is one wrapped key share addressed to a single KAS. Its
	// PolicyBinding field is an interface{}: usually a [PolicyBinding], but a
	// bare string in legacy manifests.
	//
	// See [sdk.KeyAccess].
	KeyAccess = sdk.KeyAccess

	// Method describes the payload encryption algorithm, IV, and whether the
	// payload is streamable.
	//
	// See [sdk.Method].
	Method = sdk.Method

	// Payload describes the payload entry in the archive: its type, URL, mime
	// type, and whether it is encrypted.
	//
	// See [sdk.Payload].
	Payload = sdk.Payload

	// EncryptionInformation carries the policy, key access objects, and
	// integrity information for a TDF.
	//
	// See [sdk.EncryptionInformation].
	EncryptionInformation = sdk.EncryptionInformation

	// Manifest is the TDF manifest, written to the archive as
	// 0.manifest.json.
	//
	// See [sdk.Manifest].
	Manifest = sdk.Manifest

	// Segment is one encrypted chunk of the payload plus its integrity hash.
	// Size and EncryptedSize may be omitted when they equal the manifest
	// defaults; see [sdk.Segment] for the defaulting rule, which matters when
	// writing segments.
	Segment = sdk.Segment

	// PolicyBinding is the {alg, hash} record binding a key share to the
	// policy, where hash is the HMAC keyed by that split's symmetric key.
	//
	// See [sdk.PolicyBinding].
	PolicyBinding = sdk.PolicyBinding

	// EncryptedMetadata is the AES-GCM envelope for a key access object's
	// opaque metadata.
	//
	// See [sdk.EncryptedMetadata].
	EncryptedMetadata = sdk.EncryptedMetadata
)

// PolicyAttribute is one attribute entry in a [PolicyBody]. It mirrors sdk's
// unexported attributeObject field-for-field; see [Policy] for why it is not
// an alias.
type PolicyAttribute struct {
	Attribute   string `json:"attribute"`
	DisplayName string `json:"displayName"`
	IsDefault   bool   `json:"isDefault"`
	PubKey      string `json:"pubKey"`
	KasURL      string `json:"kasURL"`
}

// Policy is the attribute policy, serialized into
// EncryptionInformation.Policy. It is JSON-identical to [sdk.PolicyObject] but
// deliberately not aliased onto it: sdk declares PolicyObject.Body as an
// anonymous struct over the unexported attributeObject, so [PolicyBody] and
// [PolicyAttribute] have no sdk names to alias, and the local ones are not
// assignable to Body. Aliasing Policy alone would break every caller naming
// the other two. For the alias to become possible, sdk would have to both
// export the attribute type and give Body a named one.
type Policy struct {
	UUID string     `json:"uuid"`
	Body PolicyBody `json:"body"`
}

// PolicyBody carries the attributes and dissem list of a [Policy].
type PolicyBody struct {
	DataAttributes []PolicyAttribute `json:"dataAttributes"`
	Dissem         []string          `json:"dissem"`
}

// These are the stable SDK's error values rather than copies of them, so
// errors.Is matches whether a caller compares against the experimental or the
// sdk-scoped name. See [Writer]'s error vars for the same pattern.
var (
	// ErrUnsupportedRootIntegrityAlgorithm rejects any root signature
	// algorithm other than HS256.
	ErrUnsupportedRootIntegrityAlgorithm = sdk.ErrUnsupportedRootIntegrityAlgorithm
	// ErrUnsupportedSegmentIntegrityAlgorithm rejects a segment algorithm that
	ErrUnsupportedSegmentIntegrityAlgorithm = sdk.ErrUnsupportedSegmentIntegrityAlgorithm
)
