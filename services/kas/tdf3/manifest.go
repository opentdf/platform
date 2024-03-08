package tdf3

type EncryptionInformation struct {
	IntegrityInformation IntegrityInformation `json:"integrityInformation"`
	KeyAccess            []KeyAccess          `json:"keyAccess"`
	Method               EncryptionMethod     `json:"method"`
	Policy               string               `json:"policy"`
	Type                 string               `json:"type"`
}

type RootSignature struct {
	Alg string `json:"alg"`
	Sig []byte `json:"sig"`
}

type Segments struct {
	EncryptedSegmentSize int    `json:"encryptedSegmentSize"`
	Hash                 []byte `json:"hash"`
	SegmentSize          int    `json:"segmentSize"`
}

type IntegrityInformation struct {
	EncryptedSegmentSizeDefault int           `json:"encryptedSegmentSizeDefault"`
	RootSignature               RootSignature `json:"rootSignature"`
	SegmentHashAlg              string        `json:"segmentHashAlg"`
	SegmentSizeDefault          int           `json:"segmentSizeDefault"`
	Segments                    []Segments    `json:"segments"`
}

type EncryptionMethod struct {
	Algorithm  string `json:"algorithm"`
	Streamable bool   `json:"isStreamable"`
	IV         []byte `json:"iv"`
}
