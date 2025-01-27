package access

import (
	"crypto"
)

type Attribute struct {
	URI           string           `json:"attribute"` // attribute
	PublicKey     crypto.PublicKey `json:"pubKey"`    // pubKey
	ProviderURI   string           `json:"kasUrl"`    // kasUrl
	SchemaVersion string           `json:"tdf_spec_version,omitempty"`
	Name          string           `json:"displayName"` // displayName
}
