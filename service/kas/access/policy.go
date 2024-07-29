package access

import (
	"github.com/google/uuid"
	"github.com/opentdf/platform/service/internal/logger/audit"
)

type Policy struct {
	UUID uuid.UUID  `json:"uuid"`
	Body PolicyBody `json:"body"`
}

type PolicyBody struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
	KeyIdentifier  string      `json:"kid"`
}

// Audit helper methods
func ConvertToAuditKasPolicy(policy Policy) audit.KasPolicy {
	return audit.KasPolicy{
		UUID: policy.UUID,
		Body: audit.KasPolicyBody{
			DataAttributes: convertToAuditKasBodyDataAttributes(policy.Body.DataAttributes),
			Dissem:         policy.Body.Dissem,
		},
	}
}

func convertToAuditKasBodyDataAttributes(dataAttributes []Attribute) []audit.KasAttribute {
	var kasAttributes []audit.KasAttribute
	for _, attribute := range dataAttributes {
		kasAttributes = append(kasAttributes, audit.KasAttribute{
			URI: attribute.URI,
		})
	}
	return kasAttributes
}
