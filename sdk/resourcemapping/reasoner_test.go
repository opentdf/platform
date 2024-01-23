package keyaccessgrants

import (
	"testing"

	attributes "github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

func av(vs ...string) []*attributes.AttributeDefinitionValue {
	a := make([]*attributes.AttributeDefinitionValue, len(vs))
	for i, v := range vs {
		a[i] = &attributes.AttributeDefinitionValue{
			Value: v,
		}
	}
	return a
}

type MockGrantService struct {
	class, relTo, needToKnow attributes.AttributeDefinition
}

func (*MockGrantService) ByAttributeValue(attr string) (*KeyAccessGrant, error) {
	panic(1)
}

func mockAttrs() GrantService {
	return &MockGrantService{
		attributes.AttributeDefinition{
			Name:   "Classification",
			Rule:   HIERARCHICAL,
			Values: av("Top Secret", "Secret", "Confidential", "For Official Use Only", "Open"),
		},
		attributes.AttributeDefinition{
			Name:   "Releasable To",
			Rule:   ANY_OF,
			Values: av("FVEY", "AUS", "CAN", "GBR", "NZL", "USA"),
		},
		attributes.AttributeDefinition{
			Name:   "Need to Know",
			Rule:   ALL_OF,
			Values: av("INT", "SI"),
		},
	}
}

func TestValid(t *testing.T) {

}
