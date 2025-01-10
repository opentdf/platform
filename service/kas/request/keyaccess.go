package request

type KeyAccess struct {
	EncryptedMetadata string      `json:"encryptedMetadata,omitempty"`
	PolicyBinding     interface{} `json:"policyBinding,omitempty"`
	Protocol          string      `json:"protocol"`
	KeyType           string      `json:"type"`
	KasURL            string      `json:"url"`
	KID               string      `json:"kid,omitempty"`
	SplitID           string      `json:"sid,omitempty"`
	WrappedKey        []byte      `json:"wrappedKey,omitempty"`
	Header            []byte      `json:"header,omitempty"`
	Algorithm         string      `json:"algorithm,omitempty"`
}
