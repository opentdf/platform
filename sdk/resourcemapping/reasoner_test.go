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

const (
	AUS_KAS    = "http://kas.au/"
	CAN_KAS    = "http://kas.ca/"
	GBR_KAS    = "http://kas.uk/"
	NZL_KAS    = "http://kas.nz/"
	USA_KAS    = "http://kas.us/"
	SI_USA_KAS = "http://si.kas.us/"
)

func (*MockGrantService) ByAttribute(attr *attributes.AttributeInstance) (*KeyAccessGrant, error) {
	var d *attributes.AttributeDefinition
	var grants []*KeyAccessGrantAttributeValue
	switch attr.Name {
	case mockAttrs().class.Name:
		d = &(mockAttrs().class)
	case mockAttrs().relTo.Name:
		d = &(mockAttrs().relTo)
		switch attr.Value {
		case "FVEY":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{AUS_KAS, CAN_KAS, GBR_KAS, NZL_KAS, USA_KAS},
			})
		case "AUS":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{AUS_KAS},
			})
		case "CAN":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{CAN_KAS},
			})
		case "GBR":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{GBR_KAS},
			})
		case "NZL":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{NZL_KAS},
			})
		case "USA":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{USA_KAS},
			})
		}
	case mockAttrs().needToKnow.Name:
		d = &(mockAttrs().needToKnow)
		switch attr.Value {
		case "INT":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{GBR_KAS},
			})
		case "SI":
			grants = append(grants, &KeyAccessGrantAttributeValue{
				KasIds: []string{SI_USA_KAS},
			})
		}
	}

	return &KeyAccessGrant{AttributeDefinition: d, AttributeValueGrants: grants}, nil
}

func mockAttrs() *MockGrantService {
	return &MockGrantService{
		attributes.AttributeDefinition{
			Name:   "Classification",
			Rule:   attributes.AttributeDefinition_AttributeRuleType(HIERARCHICAL),
			Values: av("Top Secret", "Secret", "Confidential", "For Official Use Only", "Open"),
		},
		attributes.AttributeDefinition{
			Name:   "Releasable To",
			Rule:   attributes.AttributeDefinition_AttributeRuleType(ANY_OF),
			Values: av("FVEY", "AUS", "CAN", "GBR", "NZL", "USA"),
		},
		attributes.AttributeDefinition{
			Name:   "Need to Know",
			Rule:   attributes.AttributeDefinition_AttributeRuleType(ALL_OF),
			Values: av("INT", "SI"),
		},
	}
}

func attrs(s ...string) []*attributes.AttributeInstance {
	a := make([]*attributes.AttributeInstance, len(s))
	for i, u := range s {
		var err error
		a[i], err = attributes.AttributeInstanceFromURL(u)
		if err != nil {
			panic(err)
		}
	}
	return a
}

func TestValid(t *testing.T) {
	reasoner := NewReasoner(mockAttrs())
	a1, err := reasoner.constructAttributeBoolean(attrs("https://example.com/attr/Classification/value/Secret")...)
	if err != nil {
		t.Errorf("Unexpected err [%v]", err)
	}
	if len(a1.must) != 1 || a1.must[0].def.Name != "Classification" || len(a1.must[0].values) != 0 {
		t.Errorf("Unexpected must list [%v]", a1)
	}
}
