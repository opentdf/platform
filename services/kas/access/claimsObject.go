package access

// const schemaVersion = "1.1.0"

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
