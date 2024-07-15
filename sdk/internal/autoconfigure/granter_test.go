package autoconfigure

import (
	"fmt"
	"regexp"
	"strings"
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
)

var (
	CLS, _ = NewAttributeNameFQN("https://virtru.com/attr/Classification")
	N2K, _ = NewAttributeNameFQN("https://virtru.com/attr/Need%20to%20Know")
	REL, _ = NewAttributeNameFQN("https://virtru.com/attr/Releasable%20To")

	clsA, _ = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Allowed")
	// clsC, _  = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Confidential")
	clsS, _  = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Secret")
	clsTS, _ = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Top%20Secret")

	n2kHCS, _ = NewAttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/HCS")
	n2kInt, _ = NewAttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/INT")
	n2kSI, _  = NewAttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/SI")

	// rel25eye, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/FVEY")
	rel2aus, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/AUS")
	rel2can, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/CAN")
	rel2gbr, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/GBR")
	rel2nzl, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/NZL")
	rel2usa, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/USA")
)

func spongeCase(s string) string {
	re := regexp.MustCompile(`^(https?://[\w./]+/attr/)([^/]*)(/value/)?(\S*)?$`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		panic(ErrInvalid)
	}

	var sb strings.Builder
	sb.WriteString(m[1])
	n := m[2]
	for i := 0; i < len(n); i++ {
		sub := n[i : i+1]
		if i&1 == 1 {
			sb.WriteString(strings.ToUpper(sub))
		} else {
			sb.WriteString(sub)
		}
	}
	if len(m) > 3 {
		sb.WriteString(m[3])
		v := m[4]
		for i := 0; i < len(v); i++ {
			sub := v[i : i+1]
			if i&1 == 1 {
				sb.WriteString(sub)
			} else {
				sb.WriteString(strings.ToUpper(sub))
			}
		}
	}
	return sb.String()
}

func messUpA(t *testing.T, a AttributeNameFQN) AttributeNameFQN {
	n, err := NewAttributeNameFQN(spongeCase(a.String()))
	require.NoError(t, err)
	return n
}
func messUpV(t *testing.T, a AttributeValueFQN) AttributeValueFQN {
	n, err := NewAttributeValueFQN(spongeCase(a.String()))
	require.NoError(t, err)
	return n
}

func mockAttributeFor(fqn AttributeNameFQN) *policy.Attribute {
	ns := policy.Namespace{
		Id:   "v",
		Name: "virtru.com",
		Fqn:  "https://virtru.com",
	}
	switch fqn.key {
	case CLS.key:
		return &policy.Attribute{
			Id:        "CLS",
			Namespace: &ns,
			Name:      "Classification",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Fqn:       fqn.String(),
		}
	case N2K.key:
		return &policy.Attribute{
			Id:        "N2K",
			Namespace: &ns,
			Name:      "Need to Know",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Fqn:       fqn.String(),
		}
	case REL.key:
		return &policy.Attribute{
			Id:        "REL",
			Namespace: &ns,
			Name:      "Releasable To",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
		}
	}
	return nil
}
func mockValueFor(fqn AttributeValueFQN) *policy.Value {
	an := fqn.Prefix()
	a := mockAttributeFor(an)
	v := fqn.Value()
	p := policy.Value{
		Id:        a.GetId() + ":" + v,
		Attribute: a,
		Value:     v,
		Fqn:       fqn.String(),
	}

	switch an.key {
	case N2K.key:
		switch strings.ToUpper(fqn.Value()) {
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

	case REL.key:
		switch strings.ToUpper(fqn.Value()) {
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
	case CLS.key:
		// defaults only
	}
	return &p
}

func TestAttributeFromURL(t *testing.T) {
	for _, tc := range []struct {
		n, u       string
		auth, name string
	}{
		{"letter", "http://e/attr/a", "http://e", "a"},
		{"number", "http://e/attr/1", "http://e", "1"},
		{"emoji", "http://e/attr/%F0%9F%98%81", "http://e", "😁"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			a, err := NewAttributeNameFQN(tc.u)
			require.NoError(t, err)
			assert.Equal(t, tc.auth, a.Authority())
			assert.Equal(t, tc.name, a.Name())
		})
	}
}

func TestAttributeFromMalformedURL(t *testing.T) {
	for _, tc := range []struct {
		n, u string
	}{
		{"no name", "http://e/attr"},
		{"invalid prefix 1", "hxxp://e/attr/a"},
		{"invalid prefix 2", "e/attr/a"},
		{"invalid prefix 3", "file://e/attr/a"},
		{"invalid prefix 4", "http:///attr/a"},
		{"bad encoding", "https://a/attr/%😁"},
		{"with value", "http://e/attr/a/value/b"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			a, err := NewAttributeNameFQN(tc.u)
			require.ErrorIs(t, err, ErrInvalid)
			assert.Equal(t, "", a.String())
		})
	}
}

func TestAttributeValueFromURL(t *testing.T) {
	for _, tc := range []struct {
		n, u              string
		auth, name, value string
	}{
		{"number", "http://e/attr/a/value/1", "http://e", "a", "1"},
		{"space", "http://e/attr/a/value/%20", "http://e", "a", " "},
		{"emoji", "http://e/attr/a/value/%F0%9F%98%81", "http://e", "a", "😁"},
		{"numberdef", "http://e/attr/1/value/one", "http://e", "1", "one"},
		{"valuevalue", "http://e/attr/value/value/one", "http://e", "value", "one"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			a, err := NewAttributeValueFQN(tc.u)
			require.NoError(t, err)
			assert.Equal(t, tc.auth, a.Authority())
			assert.Equal(t, tc.name, a.Name())
			assert.Equal(t, tc.value, a.Value())
		})
	}
}

func TestAttributeValueFromMalformedURL(t *testing.T) {
	for _, tc := range []struct {
		n, u string
	}{
		{"no name", "http://e/attr/value/1"},
		{"no value", "http://e/attr/who/value"},
		{"invalid prefix 1", "hxxp://e/attr/a/value/1"},
		{"invalid prefix 2", "e/attr/a/a/value/1"},
		{"bad encoding", "https://a/attr/emoji/value/%😁"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			a, err := NewAttributeValueFQN(tc.u)
			require.ErrorIs(t, err, ErrInvalid)
			assert.Equal(t, "", a.String())
		})
	}
}

func valuesToPolicy(p ...AttributeValueFQN) []*policy.Value {
	v := make([]*policy.Value, len(p))
	for i, ai := range p {
		v[i] = mockValueFor(ai)
	}
	return v
}

func TestConfigurationServicePutGet(t *testing.T) {
	for _, tc := range []struct {
		n      string
		policy []AttributeValueFQN
		size   int
		kases  []string
	}{
		{"default", []AttributeValueFQN{clsA}, 1, []string{}},
		{"one-country", []AttributeValueFQN{rel2gbr}, 1, []string{kasUk}},
		{"two-country", []AttributeValueFQN{rel2gbr, rel2nzl}, 2, []string{kasUk, kasNz}},
		{"with-default", []AttributeValueFQN{clsA, rel2gbr}, 2, []string{kasUk}},
		{"need-to-know", []AttributeValueFQN{clsTS, rel2usa, n2kSI}, 3, []string{kasUs, kasUsSA}},
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
		policy              []AttributeValueFQN
		defaults            []string
		ats, keyed, reduced string
		plan                []SplitStep
	}{
		{
			"one actual with default",
			[]AttributeValueFQN{clsS, rel2can},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/CAN",
			"[DEFAULT]&(http://kas.ca/)",
			"(http://kas.ca/)",
			[]SplitStep{{kasCa, ""}},
		},
		{
			"one defaulted attr",
			[]AttributeValueFQN{clsS},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret",
			"[DEFAULT]",
			"",
			[]SplitStep{{kasUs, ""}},
		},
		{
			"empty policy",
			[]AttributeValueFQN{},
			[]string{kasUs},
			"∅",
			"",
			"",
			[]SplitStep{{kasUs, ""}},
		},
		{
			"old school splits",
			[]AttributeValueFQN{},
			[]string{kasAu, kasCa, kasUs},
			"∅",
			"",
			"",
			[]SplitStep{{kasAu, "1"}, {kasCa, "2"}, {kasUs, "3"}},
		},
		{
			"simple with all three ops",
			[]AttributeValueFQN{clsS, rel2gbr, n2kInt},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
			"[DEFAULT]&(http://kas.uk/)&(http://kas.uk/)",
			"(http://kas.uk/)",
			[]SplitStep{{kasUk, ""}},
		},
		{
			"compartments",
			[]AttributeValueFQN{clsS, rel2gbr, rel2usa, n2kHCS, n2kSI},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
			"[DEFAULT]&(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/⋀http://si.kas.us/)",
			"(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/)&(http://si.kas.us/)",
			[]SplitStep{{kasUk, "1"}, {kasUs, "1"}, {kasUsHCS, "2"}, {kasUsSA, "3"}},
		},
		{
			"compartments - case insensitive",
			[]AttributeValueFQN{messUpV(t, clsS), messUpV(t, rel2gbr), messUpV(t, rel2usa), messUpV(t, n2kHCS), messUpV(t, n2kSI)},
			[]string{kasUs},
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
			assert.Equal(t, strings.ToLower(tc.ats), strings.ToLower(actualAB.String()))

			actualKeyed, err := reasoner.insertKeysForAttribute(*actualAB)
			require.NoError(t, err)
			assert.Equal(t, tc.keyed, actualKeyed.String())

			r := actualKeyed.reduce()
			assert.Equal(t, tc.reduced, r.String())

			i := 0
			plan, err := reasoner.Plan(tc.defaults, func() string {
				i++
				return fmt.Sprintf("%d", i)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.plan, plan)
		})
	}
}
