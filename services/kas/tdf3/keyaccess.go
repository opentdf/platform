package tdf3

type KeyAccess struct {
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
	PolicyBinding     string `json:"policyBinding,omitempty"`
	Protocol          string `json:"protocol"`
	Type              string `json:"type"`
	URL               string `json:"url"`
	WrappedKey        []byte `json:"wrappedKey,omitempty"`
	Header            []byte `json:"header,omitempty"`
	Algorithm         string `json:"algorithm,omitempty"`
}
