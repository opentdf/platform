package multi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockGrantService struct {
	class, needToKnow, relTo AttributeDefinition
}

type ConfigFixture struct {
	can, fvey, usa, usaHCS, usaSI, gbr EncryptionMapping
}

const (
	AUS_KAS     = "http://kas.au/"
	CAN_KAS     = "http://kas.ca/"
	GBR_KAS     = "http://kas.uk/"
	NZL_KAS     = "http://kas.nz/"
	USA_KAS     = "http://kas.us/"
	HCS_USA_KAS = "http://hcs.kas.us/"
	SI_USA_KAS  = "http://si.kas.us/"
	authority   = "https://virtru.com/"
)

func (gs *MockGrantService) ByAttribute(attr *AttributeInstance) (*KeyAccessGrant, error) {
	var kases []string
	var d AttributeDefinition
	switch attr.name {
	case gs.class.name:
		d = gs.class
	case gs.relTo.name:
		d = gs.relTo
		switch attr.value {
		case "FVEY":
			kases = []string{AUS_KAS, CAN_KAS, GBR_KAS, NZL_KAS, USA_KAS}
		case "AUS":
			kases = []string{AUS_KAS}
		case "CAN":
			kases = []string{CAN_KAS}
		case "GBR":
			kases = []string{GBR_KAS}
		case "NZL":
			kases = []string{NZL_KAS}
		case "USA":
			kases = []string{USA_KAS}
		}
	case gs.needToKnow.name:
		d = gs.needToKnow
		switch attr.value {
		case "INT":
			kases = []string{GBR_KAS}
		case "HCS":
			kases = []string{HCS_USA_KAS}
		case "SI":
			kases = []string{SI_USA_KAS}
		}
	}
	return &KeyAccessGrant{
		attr:  &d,
		kases: kases,
	}, nil
}

func mockAttrs() *MockGrantService {
	return &MockGrantService{
		AttributeDefinition{
			authority: authority,
			name:      "Classification",
			rule:      hierarchy,
			order:     []string{"Top Secret", "Secret", "Confidential", "For Official Use Only", "Open"},
		},
		AttributeDefinition{
			authority: authority,
			name:      "Need to Know",
			rule:      allOf,
			order:     []string{"HCS", "INT", "SI"},
		},
		AttributeDefinition{
			authority: authority,
			name:      "Releasable To",
			rule:      anyOf,
			order:     []string{"FVEY", "AUS", "CAN", "GBR", "NZL", "USA"},
		},
	}
}

func TestDefinitionSimple(t *testing.T) {
	gs := mockAttrs()
	for _, tc := range []struct {
		e string
		a AttributeDefinition
	}{
		{"https://virtru.com/attr/Classification", gs.class},
		{"https://virtru.com/attr/Need%20to%20Know", gs.needToKnow},
		{"https://virtru.com/attr/Releasable%20To", gs.relTo},
	} {
		t.Run(tc.e, func(t *testing.T) {
			assert.Equal(t, tc.e, tc.a.Prefix())
		})
	}
}
func TestAttributeInstanceString(t *testing.T) {
	for _, tc := range []struct {
		title             string
		auth, name, value string
		e                 string
	}{
		{"good", "http://e/", "a", "1", "http://e/attr/a/value/1"},
		{"with slash in attr", "http://e/", "attr/value", "value", "http://e/attr/attr%2Fvalue/value/value"},
		{"with space in attr", "http://e/", "a b", "1", "http://e/attr/a%20b/value/1"},
		{"with %", "http://e/", "hello there%", "#", "http://e/attr/hello%20there%25/value/%23"},
	} {
		t.Run(tc.e, func(t *testing.T) {
			assert.Equal(t, tc.e, AttributeInstance{tc.auth, tc.name, tc.value}.String())
		})
	}
}

func TestAttributeInstanceFromURL(t *testing.T) {
	for _, tc := range []struct {
		u                 string
		auth, name, value string
	}{
		{"http://e/attr/a/value/1", "http://e", "a", "1"},
		// {"http://E/attr/a/value/1", "http://e/", "a", "1"},
		{"http://e/attr/a/value/%20", "http://e", "a", " "},
	} {
		t.Run(tc.u, func(t *testing.T) {
			a, err := fromURL(tc.u)
			require.NoError(t, err)
			assert.Equal(t, tc.auth, a.authority)
			assert.Equal(t, tc.name, a.name)
			assert.Equal(t, tc.value, a.value)
		})
	}
}

func TestGrantServicePutGet(t *testing.T) {
	var s AttributeService
	gs := mockAttrs()
	for _, d := range []AttributeDefinition{
		gs.class, gs.needToKnow, gs.relTo,
	} {
		d2 := d
		s.Put(&d2)
	}

	for _, tc := range []struct {
		ad     AttributeDefinition
		prefix string
	}{
		{gs.class, gs.class.Prefix()},
		{gs.needToKnow, gs.needToKnow.Prefix()},
		{gs.relTo, gs.relTo.Prefix()},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			a, err := s.Get(tc.prefix)
			require.NoError(t, err)
			assert.Equal(t, tc.ad, *a, s)
		})
	}
}

func configFixture(gs *MockGrantService) ConfigFixture {
	return ConfigFixture{
		can:    EncryptionMapping{CAN_KAS, []KeyAccessGrant{{&gs.relTo, []string{"CAN"}}}},
		usa:    EncryptionMapping{USA_KAS, []KeyAccessGrant{{&gs.relTo, []string{"USA"}}}},
		usaHCS: EncryptionMapping{HCS_USA_KAS, []KeyAccessGrant{{&gs.needToKnow, []string{"HCS"}}}},
		usaSI:  EncryptionMapping{SI_USA_KAS, []KeyAccessGrant{{&gs.needToKnow, []string{"SI"}}}},
		gbr: EncryptionMapping{GBR_KAS, []KeyAccessGrant{
			{&gs.needToKnow, []string{"INT"}},
			{&gs.relTo, []string{"GBR"}},
		}},
	}
}

func TestConfigurationServicePutGet(t *testing.T) {
	gs := mockAttrs()
	cfg := configFixture(gs)
	cs := NewConfigurationService()

	assert.Empty(t, cs.ForAttr("https://virtru.com/attr/Classification"))

	cs.Put(&cfg.gbr)
	cs.Put(&cfg.usa)
	assert.Len(t, cs.ForAttr("https://virtru.com/attr/Need%20to%20Know"), 1)
	assert.Len(t, cs.ForAttr("https://virtru.com/attr/Releasable%20To"), 2)
	assert.Empty(t, cs.ForAttr("https://virtru.com/attr/Classification"))

	cs.Put(&cfg.usaHCS)
	cs.Put(&cfg.usaSI)
	assert.Len(t, cs.ForAttr("https://virtru.com/attr/Need%20to%20Know"), 3)
}

func attrs(s ...string) []*AttributeInstance {
	a := make([]*AttributeInstance, len(s))
	for i, u := range s {
		var err error
		a[i], err = fromURL(u)
		if err != nil {
			panic(err)
		}
	}
	return a
}

func TestValid(t *testing.T) {
	reasoner := NewReasoner(mockAttrs())
	a1, err := reasoner.constructAttributeBoolean(attrs("https://example.com/attr/Classification/value/Secret")...)
	require.NoError(t, err)
	assert.Len(t, a1.must, 1)
	assert.Equal(t, "Classification", a1.must[0].def.name)
}

func auri(t *testing.T, a *AttributeDefinition, v string) *AttributeInstance {
	u, err := a.Select(v)
	require.NoError(t, err)
	require.NotNil(t, u)
	return u
}

func TestReasonerConstructAttributeBoolean(t *testing.T) {
	gs := mockAttrs()
	reasoner := NewReasoner(gs)

	for _, tc := range []struct {
		n      string
		policy []*AttributeInstance

		ats, keyed, reduced string
	}{
		{
			"one actual with default",
			[]*AttributeInstance{
				auri(t, &gs.class, "Secret"),
				auri(t, &gs.relTo, "CAN"),
			},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/CAN",
			"[DEFAULT]&(http://kas.ca/)",
			"(http://kas.ca/)",
		},
		{
			"one defaulted attr",
			[]*AttributeInstance{
				auri(t, &gs.class, "Secret"),
			},
			"https://virtru.com/attr/Classification/value/Secret",
			"[DEFAULT]",
			"",
		},
		{
			"empty policy",
			[]*AttributeInstance{},
			"∅",
			"",
			"",
		},
		{
			"simple with all three ops",
			[]*AttributeInstance{
				auri(t, &gs.class, "Secret"),
				auri(t, &gs.relTo, "GBR"),
				auri(t, &gs.needToKnow, "INT"),
			},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
			"[DEFAULT]&(http://kas.uk/)&(http://kas.uk/)",
			"(http://kas.uk/)",
		},
		{
			"compartments",
			[]*AttributeInstance{
				auri(t, &gs.class, "Secret"),
				auri(t, &gs.relTo, "GBR"),
				auri(t, &gs.relTo, "USA"),
				auri(t, &gs.needToKnow, "HCS"),
				auri(t, &gs.needToKnow, "SI"),
			},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
			"[DEFAULT]&(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/⋀http://si.kas.us/)",
			"(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/)&(http://si.kas.us/)",
		},
	} {
		t.Run(tc.n, func(t *testing.T) {
			actualAB, err := reasoner.constructAttributeBoolean(tc.policy...)
			require.NoError(t, err)
			assert.Equal(t, tc.ats, actualAB.String())

			actualKeyed, err := reasoner.insertKeysForAttribute(*actualAB)
			require.NoError(t, err)
			assert.Equal(t, tc.keyed, actualKeyed.String())

			r := actualKeyed.reduce()
			assert.Equal(t, tc.reduced, r.String())
		})
	}
}
