// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"github.com/opentdf/platform/sdk"
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
