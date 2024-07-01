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
	kasAu     = "http://kas.au/"
	kasCa     = "http://kas.ca/"
	kasUk     = "http://kas.uk/"
	kasNz     = "http://kas.nz/"
	kasUs     = "http://kas.us/"
	kasUsHCS  = "http://hcs.kas.us/"
	kasUsSA   = "http://si.kas.us/"
	authority = "https://virtru.com/"

	CLS AttributeName = "https://virtru.com/attr/Classification"
	N2K AttributeName = "https://virtru.com/attr/Need%20to%20Know"
	REL AttributeName = "https://virtru.com/attr/Releasable%20To"

	clsA  AttributeValue = "https://virtru.com/attr/Classification/value/Allowed"
	clsC  AttributeValue = "https://virtru.com/attr/Classification/value/Confidential"
	clsS  AttributeValue = "https://virtru.com/attr/Classification/value/Secret"
	clsTS AttributeValue = "https://virtru.com/attr/Classification/value/Top%20Secret"

	n2kHCS AttributeValue = "https://virtru.com/attr/Need%20to%20Know/value/HCS"
	n2kInt AttributeValue = "https://virtru.com/attr/Need%20to%20Know/value/INT"
	n2kSI  AttributeValue = "https://virtru.com/attr/Need%20to%20Know/value/SI"

	rel25eye AttributeValue = "https://virtru.com/attr/Releasable%20To/value/FVEY"
	rel2aus  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/AUS"
	rel2can  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/CAN"
	rel2gbr  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/GBR"
	rel2nzl  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/NZL"
	rel2usa  AttributeValue = "https://virtru.com/attr/Releasable%20To/value/USA"
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
	a := mockAttributeFor(an)
	v := fqn.Value()
	p := policy.Value{
		Id:        a.GetId() + ":" + v,
		Attribute: a,
		Value:     v,
		Fqn:       string(fqn),
	}

	switch an {
	case N2K:
		switch fqn.Value() {
		case "INT":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUk}
		case "HCS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUsHCS}
		case "SI":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUsSA}
		}

	case REL:
		switch fqn.Value() {
		case "FVEY":
			p.Grants = make([]*policy.KeyAccessServer, 5)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasAu}
			p.Grants[1] = &policy.KeyAccessServer{Uri: kasCa}
			p.Grants[2] = &policy.KeyAccessServer{Uri: kasUk}
			p.Grants[3] = &policy.KeyAccessServer{Uri: kasNz}
			p.Grants[4] = &policy.KeyAccessServer{Uri: kasUs}
		case "AUS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasAu}
		case "CAN":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasCa}
		case "GBR":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUk}
		case "NZL":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasNz}
		case "USA":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUs}
		}
	case CLS:
		// defaults only
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
		{"default", []AttributeValue{clsA}, 1, []string{}},
		{"one-country", []AttributeValue{rel2gbr}, 1, []string{kasUk}},
		{"two-country", []AttributeValue{rel2gbr, rel2nzl}, 2, []string{kasUk, kasNz}},
		{"with-default", []AttributeValue{clsA, rel2gbr}, 2, []string{kasUk}},
		{"need-to-know", []AttributeValue{clsTS, rel2usa, n2kSI}, 3, []string{kasUs, kasUsSA}},
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
			[]AttributeValue{clsS, rel2can},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/CAN",
			"[DEFAULT]&(http://kas.ca/)",
			"(http://kas.ca/)",
			[]SplitStep{{kasCa, ""}},
		},
		{
			"one defaulted attr",
			[]AttributeValue{clsS},
			"https://virtru.com/attr/Classification/value/Secret",
			"[DEFAULT]",
			"",
			[]SplitStep{{kasUs, ""}},
		},
		{
			"empty policy",
			[]AttributeValue{},
			"∅",
			"",
			"",
			[]SplitStep{{kasUs, ""}},
		},
		{
			"simple with all three ops",
			[]AttributeValue{clsS, rel2gbr, n2kInt},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
			"[DEFAULT]&(http://kas.uk/)&(http://kas.uk/)",
			"(http://kas.uk/)",
			[]SplitStep{{kasUk, ""}},
		},
		{
			"compartments",
			[]AttributeValue{clsS, rel2gbr, rel2usa, n2kHCS, n2kSI},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
			"[DEFAULT]&(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/⋀http://si.kas.us/)",
			"(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/)&(http://si.kas.us/)",
			[]SplitStep{{kasUk, "1"}, {kasUs, "1"}, {kasUsHCS, "2"}, {kasUsSA, "3"}},
		},
	} {
		t.Run(tc.n, func(t *testing.T) {
			reasoner, err := NewGranterFromAttributes(valuesToPolicy(tc.policy...)...)
			require.NoError(t, err)

			actualAB := reasoner.constructAttributeBoolean()
			assert.Equal(t, tc.ats, actualAB.String())

			actualKeyed, err := reasoner.insertKeysForAttribute(*actualAB)
			require.NoError(t, err)
			assert.Equal(t, tc.keyed, actualKeyed.String())

			r := actualKeyed.reduce()
			assert.Equal(t, tc.reduced, r.String())

			i := 0
			plan, err := reasoner.Plan(kasUs, func() string {
				i++
				return fmt.Sprintf("%d", i)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.plan, plan)
		})
	}
}
