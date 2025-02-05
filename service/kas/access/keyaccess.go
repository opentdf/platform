package access

type KeyAccess struct {
	EncryptedMetadata string      `json:"encryptedMetadata,omitempty"`
	PolicyBinding     interface{} `json:"policyBinding,omitempty"`
	Protocol          string      `json:"protocol"`
	Type              string      `json:"type"`
	URL               string      `json:"url"`
	KID               string      `json:"kid,omitempty"`
	SID               string      `json:"sid,omitempty"`
	WrappedKey        []byte      `json:"wrappedKey,omitempty"`
	Header            []byte      `json:"header,omitempty"`
	Algorithm         string      `json:"algorithm,omitempty"`
}
