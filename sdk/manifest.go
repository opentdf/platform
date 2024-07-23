package sdk

type Segment struct {
	Hash          string `json:"hash"`
	Size          int64  `json:"segmentSize"`
	EncryptedSize int64  `json:"encryptedSegmentSize"`
}

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
	KeyType           string        `json:"type"`
	KasURL            string        `json:"url"`
	Protocol          string        `json:"protocol"`
	WrappedKey        string        `json:"wrappedKey"`
	PolicyBinding     PolicyBinding `json:"policyBinding"`
	EncryptedMetadata string        `json:"encryptedMetadata,omitempty"`
	KID               string        `json:"kid,omitempty"`
	SplitID           string        `json:"sid,omitempty"`
}

type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
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

type Statement struct {
	Format string `json:"format,omitempty"`
	Value  string `json:"value,omitempty"`
}

type Binding struct {
	Method    string `json:"method,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type Assertion struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Scope        string    `json:"scope"`
	AppliedState string    `json:"appliesToState,omitempty"`
	Statement    Statement `json:"statement"`
	Binding      Binding   `json:"binding"`
}

type Manifest struct {
	EncryptionInformation `json:"encryptionInformation"`
	Payload               `json:"payload"`
	Assertions            []Assertion `json:"assertions"`
}

type attributeObject struct {
	Attribute   string `json:"attribute"`
	DisplayName string `json:"displayName"`
	IsDefault   bool   `json:"isDefault"`
	PubKey      string `json:"pubKey"`
	KasURL      string `json:"kasURL"`
}

type PolicyObject struct {
	UUID string `json:"uuid"`
	Body struct {
		DataAttributes []attributeObject `json:"dataAttributes"`
		Dissem         []string          `json:"dissem"`
	} `json:"body"`
}

type EncryptedMetadata struct {
	Cipher string `json:"ciphertext"`
	Iv     string `json:"iv"`
}
