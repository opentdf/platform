package access

import (
	"github.com/google/uuid"
	"github.com/opentdf/platform/service/internal/logger"
)

type Policy struct {
	UUID uuid.UUID  `json:"uuid"`
	Body PolicyBody `json:"body"`
}

type PolicyBody struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
}

// Audit helper methods
func ConvertToAuditKasPolicy(policy Policy) logger.KasPolicy {
	return logger.KasPolicy{
		UUID: policy.UUID,
		Body: logger.KasPolicyBody{
			DataAttributes: convertToAuditKasBodyDataAttributes(policy.Body.DataAttributes),
			Dissem:         policy.Body.Dissem,
		},
	}
}

func convertToAuditKasBodyDataAttributes(dataAttributes []Attribute) []logger.KasAttribute {
	var kasAttributes []logger.KasAttribute
	for _, attribute := range dataAttributes {
		kasAttributes = append(kasAttributes, logger.KasAttribute{
			URI: attribute.URI,
		})
	}
	return kasAttributes
}
