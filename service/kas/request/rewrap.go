package request

import "github.com/opentdf/platform/protocol/go/kas"

type PolicyRequest struct {
	Id   string `json:"id"`
	Body string `json:"body"`
}

type KeyAccessObjectRequest struct {
	KeyAccessObjectId string `json:"keyAccessObjectId"`
	KeyAccess         `json:"keyAccessObject"`

	// For Platform Use
	Processed    bool   `json:"-"`
	SymmetricKey []byte `json:"-"`
	Err          error  `json"-"`
}

type RewrapRequests struct {
	KeyAccessObjectRequests []*KeyAccessObjectRequest `json:"keyAccessObjects"`
	Policy                  PolicyRequest             `json:"policy"`
	Algorithm               string                    `json:"algorithm,omitempty"`

	// For Platform Use
	Results *kas.RewrapResult `json:"-"`
}

type RequestBody struct {
	Requests        []*RewrapRequests `json:"requests"`
	ClientPublicKey string            `json:"ClientPublicKey"`
}
