// Canary types for tinyjson codegen under TinyGo.
// Copied from sdk/experimental/tdf/manifest.go and assertion_types.go.
// These must stay in sync with the source structs.

//go:generate tinyjson -all types.go

package types

// ── Manifest types ───────────────────────────────────────────

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
	KeyType            string        `json:"type"`
	KasURL             string        `json:"url"`
	Protocol           string        `json:"protocol"`
	WrappedKey         string        `json:"wrappedKey"`
	PolicyBinding      PolicyBinding `json:"policyBinding"`
	EncryptedMetadata  string        `json:"encryptedMetadata,omitempty"`
	KID                string        `json:"kid,omitempty"`
	SplitID            string        `json:"sid,omitempty"`
	SchemaVersion      string        `json:"schemaVersion,omitempty"`
	EphemeralPublicKey string        `json:"ephemeralPublicKey,omitempty"`
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
}

type EncryptionInformation struct {
	KeyAccessType        string      `json:"type"`
	Policy               string      `json:"policy"`
	KeyAccessObjs        []KeyAccess `json:"keyAccess"`
	Method               Method      `json:"method"`
	IntegrityInformation `json:"integrityInformation"`
}

type Manifest struct {
	EncryptionInformation `json:"encryptionInformation"`
	Payload               `json:"payload"`
	Assertions            []Assertion `json:"assertions,omitempty"`
	TDFVersion            string      `json:"schemaVersion,omitempty"`
}

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

type Segment struct {
	Hash          string `json:"hash"`
	Size          int64  `json:"segmentSize"`
	EncryptedSize int64  `json:"encryptedSegmentSize"`
}

type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
}

type EncryptedMetadata struct {
	Cipher string `json:"ciphertext"`
	Iv     string `json:"iv"`
}

// ── Assertion types ──────────────────────────────────────────

type Assertion struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	Scope          string    `json:"scope"`
	AppliesToState string    `json:"appliesToState,omitempty"`
	Statement      Statement `json:"statement"`
	Binding        Binding   `json:"binding,omitempty"`
}

type Statement struct {
	Format string `json:"format,omitempty"`
	Schema string `json:"schema,omitempty"`
	Value  string `json:"value,omitempty"`
}

type Binding struct {
	Method    string `json:"method,omitempty"`
	Signature string `json:"signature,omitempty"`
}
