package access

import (
	"crypto"
)

const schemaVersion = "1.1.0"

type ClaimsObject struct {
	PublicKey              string        `json:"public_key"`
	ClientPublicSigningKey string        `json:"client_public_signing_key"`
	SchemaVersion          string        `json:"tdf_spec_version,omitempty"`
	Entitlements           []Entitlement `json:"entitlements"`
}

type Entitlement struct {
	EntityID         string      `json:"entity_identifier"`
	EntityAttributes []Attribute `json:"entity_attributes"`
}

type Attribute struct {
	URI           string           `json:"attribute"`
	PublicKey     crypto.PublicKey `json:"pubKey"`
	ProviderURI   string           `json:"kasUrl"`
	SchemaVersion string           `json:"tdf_spec_version,omitempty"`
	Name          string           `json:"displayName"`
}
