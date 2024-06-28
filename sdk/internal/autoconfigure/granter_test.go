package autoconfigure

import (
	"fmt"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

const (
	AUS_KAS     = "http://kas.au/"
	CAN_KAS     = "http://kas.ca/"
	GBR_KAS     = "http://kas.uk/"
	NZL_KAS     = "http://kas.nz/"
	USA_KAS     = "http://kas.us/"
	HCS_USA_KAS = "http://hcs.kas.us/"
	SI_USA_KAS  = "http://si.kas.us/"
	authority   = "https://virtru.com/"

	CLS AttributeName = "https://virtru.com/attr/Classification"
	N2K AttributeName = "https://virtru.com/attr/Need%20to%20Know"
	REL AttributeName = "https://virtru.com/attr/Releasable%20To"

	CLS_Allowed      AttributeValue = "https://virtru.com/attr/Classification/value/Allowed"
	CLS_Confidential AttributeValue = "https://virtru.com/attr/Classification/value/Confidential"
	CLS_Secret       AttributeValue = "https://virtru.com/attr/Classification/value/Secret"
	CLS_TopSecret    AttributeValue = "https://virtru.com/attr/Classification/value/Top%20Secret"

	N2K_HCS AttributeValue = "https://virtru.com/attr/Need%20to%20Know/value/HCS"
	N2K_INT AttributeValue = "https://virtru.com/attr/Need%20to%20Know/value/INT"
	N2K_SI  AttributeValue = "https://virtru.com/attr/Need%20to%20Know/value/SI"

	REL_FVEY AttributeValue = "https://virtru.com/attr/Releasable%20To/value/FVEY"
	REL_AUS  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/AUS"
	REL_CAN  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/CAN"
	REL_GBR  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/GBR"
	REL_NZL  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/NZL"
	REL_USA  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/USA"
)

func mockAttributeFor(fqn AttributeName) *policy.Attribute {
	ns := policy.Namespace{
		Id:   "v",
		Name: "virtru.com",
		Fqn:  "https://virtru.com",
	}
	switch fqn {
	case CLS:
		return &policy.Attribute{
			Id:        "CLS",
			Namespace: &ns,
			Name:      "Classification",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Fqn:       string(fqn),
		}
	case N2K:
		return &policy.Attribute{
			Id:        "N2K",
			Namespace: &ns,
			Name:      "Need to Know",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Fqn:       string(fqn),
		}
	case REL:
		return &policy.Attribute{
			Id:        "REL",
			Namespace: &ns,
			Name:      "Releasable To",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       string(fqn),
		}
	}
	return nil
}
func mockValueFor(fqn AttributeValue) *policy.Value {
	an := fqn.Prefix()
	a := mockAttributeFor(AttributeName(an))
	v := fqn.Value()
	p := policy.Value{
		Id:        a.Id + ":" + v,
		Attribute: a,
		Value:     v,
		Fqn:       string(fqn),
	}

	switch an {
	case N2K:
		switch fqn.Value() {
		case "INT":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: GBR_KAS}
		case "HCS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: HCS_USA_KAS}
		case "SI":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: SI_USA_KAS}
		}

	case REL:
		switch fqn.Value() {
		case "FVEY":
			p.Grants = make([]*policy.KeyAccessServer, 5)
			p.Grants[0] = &policy.KeyAccessServer{Uri: AUS_KAS}
			p.Grants[1] = &policy.KeyAccessServer{Uri: CAN_KAS}
			p.Grants[2] = &policy.KeyAccessServer{Uri: GBR_KAS}
			p.Grants[3] = &policy.KeyAccessServer{Uri: NZL_KAS}
			p.Grants[4] = &policy.KeyAccessServer{Uri: USA_KAS}
		case "AUS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: AUS_KAS}
		case "CAN":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: CAN_KAS}
		case "GBR":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: GBR_KAS}
		case "NZL":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: NZL_KAS}
		case "USA":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: USA_KAS}
		}
	}
	return &p
}

func TestAttributeInstanceFromURL(t *testing.T) {
	for _, tc := range []struct {
		n, u              string
		auth, name, value string
	}{
		{"number", "http://e/attr/a/value/1", "http://e", "a", "1"},
		{"space", "http://e/attr/a/value/%20", "http://e", "a", " "},
		{"emoji", "http://e/attr/a/value/%F0%9F%98%81", "http://e", "a", "😁"},
		{"numberdef", "http://e/attr/1/value/one", "http://e", "1", "one"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			a, err := NewAttributeValue(tc.u)
			require.NoError(t, err)
			assert.Equal(t, tc.auth, a.Authority())
			assert.Equal(t, tc.name, a.Name())
			assert.Equal(t, tc.value, a.Value())
		})
	}
}

func valuesToPolicy(p ...AttributeValue) []*policy.Value {
	v := make([]*policy.Value, len(p))
	for i, ai := range p {
		v[i] = mockValueFor(ai)
	}
	return v
}

func TestConfigurationServicePutGet(t *testing.T) {
	for _, tc := range []struct {
		n      string
		policy []AttributeValue
		size   int
		kases  []string
	}{
		{"default", []AttributeValue{CLS_Allowed}, 1, []string{}},
		{"one-country", []AttributeValue{REL_GBR}, 1, []string{GBR_KAS}},
		{"two-country", []AttributeValue{REL_GBR, REL_NZL}, 2, []string{GBR_KAS, NZL_KAS}},
		{"with-default", []AttributeValue{CLS_Allowed, REL_GBR}, 2, []string{GBR_KAS}},
		{"need-to-know", []AttributeValue{CLS_TopSecret, REL_USA, N2K_SI}, 3, []string{USA_KAS, SI_USA_KAS}},
	} {
		t.Run(tc.n, func(t *testing.T) {
			v := valuesToPolicy(tc.policy...)
			grants, err := NewGranterFromAttributes(v...)
			require.NoError(t, err)
			assert.Len(t, grants.grants, tc.size)
			assert.Subset(t, tc.policy, maps.Keys(grants.grants))
			actualKases := make(map[string]bool)
			for _, g := range grants.grants {
				require.NotNil(t, g)
				for _, k := range g.kases {
					actualKases[k] = true
				}
			}
			assert.ElementsMatch(t, tc.kases, maps.Keys(actualKases))
		})
	}
}

func TestReasonerConstructAttributeBoolean(t *testing.T) {
	for _, tc := range []struct {
		n                   string
		policy              []AttributeValue
		ats, keyed, reduced string
		plan                []SplitStep
	}{
		{
			"one actual with default",
			[]AttributeValue{CLS_Secret, REL_CAN},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/CAN",
			"[DEFAULT]&(http://kas.ca/)",
			"(http://kas.ca/)",
			[]SplitStep{{CAN_KAS, ""}},
		},
		{
			"one defaulted attr",
			[]AttributeValue{CLS_Secret},
			"https://virtru.com/attr/Classification/value/Secret",
			"[DEFAULT]",
			"",
			[]SplitStep{{USA_KAS, ""}},
		},
		{
			"empty policy",
			[]AttributeValue{},
			"∅",
			"",
			"",
			[]SplitStep{{USA_KAS, ""}},
		},
		{
			"simple with all three ops",
			[]AttributeValue{CLS_Secret, REL_GBR, N2K_INT},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
			"[DEFAULT]&(http://kas.uk/)&(http://kas.uk/)",
			"(http://kas.uk/)",
			[]SplitStep{{GBR_KAS, ""}},
		},
		{
			"compartments",
			[]AttributeValue{CLS_Secret, REL_GBR, REL_USA, N2K_HCS, N2K_SI},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
			"[DEFAULT]&(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/⋀http://si.kas.us/)",
			"(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/)&(http://si.kas.us/)",
			[]SplitStep{{GBR_KAS, "1"}, {USA_KAS, "1"}, {HCS_USA_KAS, "2"}, {SI_USA_KAS, "3"}},
		},
	} {
		t.Run(tc.n, func(t *testing.T) {
			reasoner, err := NewGranterFromAttributes(valuesToPolicy(tc.policy...)...)
			require.NoError(t, err)

			actualAB, err := reasoner.constructAttributeBoolean()
			require.NoError(t, err)
			assert.Equal(t, tc.ats, actualAB.String())

			actualKeyed, err := reasoner.insertKeysForAttribute(*actualAB)
			require.NoError(t, err)
			assert.Equal(t, tc.keyed, actualKeyed.String())

			r := actualKeyed.reduce()
			assert.Equal(t, tc.reduced, r.String())

			i := 0
			plan, err := reasoner.Plan(USA_KAS, func() string {
				i++
				return fmt.Sprintf("%d", i)
			})
			assert.Equal(t, tc.plan, plan)
		})
	}
}
