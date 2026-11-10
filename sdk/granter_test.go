package sdk

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	kasAu               = "https://kas.au/"
	kasCa               = "https://kas.ca/"
	kasUk               = "https://kas.uk/"
	kasNz               = "https://kas.nz/"
	kasUs               = "https://kas.us/"
	kasUsHCS            = "https://hcs.kas.us/"
	kasUsSA             = "https://si.kas.us/"
	specifiedKas        = "https://attr.kas.com/"
	evenMoreSpecificKas = "https://value.kas.com/"
	lessSpecificKas     = "https://namespace.kas.com/"
	obligationKas       = "https://obligation.kas.com/"
	fakePem             = mockRSAPublicKey1
)

var (
	CLS, _ = NewAttributeNameFQN("https://virtru.com/attr/Classification")
	N2K, _ = NewAttributeNameFQN("https://virtru.com/attr/Need%20to%20Know")
	REL, _ = NewAttributeNameFQN("https://virtru.com/attr/Releasable%20To")

	clsA, _  = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Allowed")
	clsS, _  = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Secret")
	clsTS, _ = NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Top%20Secret")

	n2kHCS, _ = NewAttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/HCS")
	n2kInt, _ = NewAttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/INT")
	n2kSI, _  = NewAttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/SI")

	rel2aus, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/AUS")
	rel2can, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/CAN")
	rel2gbr, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/GBR")
	rel2nzl, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/NZL")
	rel2usa, _ = NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/USA")

	// attributes to test specificity of kas grants
	UNSPECKED, _ = NewAttributeNameFQN("https://other.com/attr/unspecified")
	SPECKED, _   = NewAttributeNameFQN("https://other.com/attr/specified")
	uns2uns, _   = NewAttributeValueFQN("https://other.com/attr/unspecified/value/unspecked")
	uns2spk, _   = NewAttributeValueFQN("https://other.com/attr/unspecified/value/specked")
	spk2uns, _   = NewAttributeValueFQN("https://other.com/attr/specified/value/unspecked")
	spk2spk, _   = NewAttributeValueFQN("https://other.com/attr/specified/value/specked")

	// with namsepace that has grants
	SPKUNSPECKED, _ = NewAttributeNameFQN("https://hasgrants.com/attr/unspecified")
	SPKSPECKED, _   = NewAttributeNameFQN("https://hasgrants.com/attr/specified")
	spk2uns2uns, _  = NewAttributeValueFQN("https://hasgrants.com/attr/unspecified/value/unspecked")
	spk2uns2spk, _  = NewAttributeValueFQN("https://hasgrants.com/attr/unspecified/value/specked")
	spk2spk2uns, _  = NewAttributeValueFQN("https://hasgrants.com/attr/specified/value/unspecked")
	spk2spk2spk, _  = NewAttributeValueFQN("https://hasgrants.com/attr/specified/value/specked")

	// Attributes for testing specific key mapping
	MP, _  = NewAttributeNameFQN("https://virtru.com/attr/mapped")
	mpa, _ = NewAttributeValueFQN("https://virtru.com/attr/mapped/value/a")
	mpb, _ = NewAttributeValueFQN("https://virtru.com/attr/mapped/value/b")
	mpc, _ = NewAttributeValueFQN("https://virtru.com/attr/mapped/value/c")
	mpd, _ = NewAttributeValueFQN("https://virtru.com/attr/mapped/value/d")
	mpu, _ = NewAttributeValueFQN("https://virtru.com/attr/mapped/value/unspecified")

	// Attributes for testing obligations

	OBLIGATIONATTR, _   = NewAttributeNameFQN("https://virtru.com/attr/obligation_test")
	oa1, _              = NewAttributeValueFQN("https://virtru.com/attr/obligation_test/value/value1")
	oa2, _              = NewAttributeValueFQN("https://virtru.com/attr/obligation_test/value/value2")
	oa3, _              = NewAttributeValueFQN("https://virtru.com/attr/obligation_test/value/value3")
	obligationWatermark = "https://virtru.com/obl/obligation_test/value/watermark"
	obligationGeofence  = "https://virtru.com/obl/obligation_test/value/geofence"
	obligationRedact    = "https://virtru.com/obl/obligation_test/value/redact"
	obligationMap       = map[string]string{
		oa1.key: obligationWatermark,
		oa2.key: obligationGeofence,
		oa3.key: obligationRedact,
	}
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

func messUpV(t *testing.T, a AttributeValueFQN) AttributeValueFQN {
	n, err := NewAttributeValueFQN(spongeCase(a.String()))
	require.NoError(t, err)
	return n
}

func mockAttributeFor(fqn AttributeNameFQN) *policy.Attribute {
	nsOne := policy.Namespace{
		Id:   "v",
		Name: "virtru.com",
		Fqn:  "https://virtru.com",
	}
	nsTwo := policy.Namespace{
		Id:   "o",
		Name: "other.com",
		Fqn:  "https://other.com",
	}
	// h := make([]*policy.KeyAccessServer, 1)
	// h[0] = mockGrant(lessSpecificKas, "r1")
	nsThree := policy.Namespace{
		Id:     "h",
		Name:   "hasgrants.com",
		Fqn:    "https://hasgrants.com",
		Grants: []*policy.KeyAccessServer{{Uri: lessSpecificKas}},
	}
	switch fqn.key {
	case CLS.key:
		return &policy.Attribute{
			Id:        "CLS",
			Namespace: &nsOne,
			Name:      "Classification",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Fqn:       fqn.String(),
		}
	case MP.key:
		g := make([]*policy.KeyAccessServer, 1)
		g[0] = mockGrant(specifiedKas, "r1")
		return &policy.Attribute{
			Id:        "MP",
			Namespace: &nsOne,
			Name:      "Mapped",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
			Grants:    g,
			KasKeys:   []*policy.SimpleKasKey{mockSimpleKasKey(specifiedKas, "r1")},
		}
	case N2K.key:
		return &policy.Attribute{
			Id:        "N2K",
			Namespace: &nsOne,
			Name:      "Need to Know",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Fqn:       fqn.String(),
		}
	case REL.key:
		return &policy.Attribute{
			Id:        "REL",
			Namespace: &nsOne,
			Name:      "Releasable To",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
		}
	case SPECKED.key:
		g := make([]*policy.KeyAccessServer, 1)
		g[0] = mockGrant(specifiedKas, "r1")
		return &policy.Attribute{
			Id:        "SPK",
			Namespace: &nsTwo,
			Name:      "specified",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
			Grants:    g,
		}
	case UNSPECKED.key:
		return &policy.Attribute{
			Id:        "UNS",
			Namespace: &nsTwo,
			Name:      "unspecified",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
		}
	case SPKSPECKED.key:
		g := make([]*policy.KeyAccessServer, 1)
		g[0] = mockGrant(specifiedKas, "r1")
		return &policy.Attribute{
			Id:        "SPK",
			Namespace: &nsThree,
			Name:      "specified",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
			Grants:    g,
		}
	case SPKUNSPECKED.key:
		return &policy.Attribute{
			Id:        "UNS",
			Namespace: &nsThree,
			Name:      "unspecified",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
		}
	case OBLIGATIONATTR.key:
		return &policy.Attribute{
			Id:        "OBL",
			Namespace: &nsOne,
			Name:      "obligation",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
		}
	}
	return nil
}

func mockGrant(kas, kid string) *policy.KeyAccessServer {
	if kas == "" {
		panic("invalid kas URI")
	}
	if kid == "" {
		return mockGrant(kas, "r0")
	}

	var k policy.SimpleKasPublicKey
	switch kid {
	case "r0":
		k = policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       kid,
			Pem:       fakePem,
		}
	case "r1":
		k = policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       kid,
			Pem:       mockRSAPublicKey1,
		}
	case "r2":
		k = policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_4096,
			Kid:       kid,
			Pem:       mockRSAPublicKey2,
		}
	case "r3":
		k = policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       kid,
			Pem:       mockRSAPublicKey3,
		}
	case "e1":
		k = policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_EC_P256,
			Kid:       kid,
			Pem:       mockECPublicKey1,
		}
	case "e2":
		k = policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_EC_P256,
			Kid:       kid,
			Pem:       mockECPublicKey2,
		}
	default:
		panic("invalid kas kid: " + kid)
	}

	return &policy.KeyAccessServer{
		Uri: kas,
		Id:  kas,
		KasKeys: []*policy.SimpleKasKey{
			{
				KasUri:    kas,
				PublicKey: &k,
			},
		},
	}
}

type fakeKeyInfoFetcher struct{}

func (f *fakeKeyInfoFetcher) getPublicKey(_ context.Context, kasurl, _, _ string) (*KASInfo, error) {
	if kasurl == "" {
		return nil, errors.New("kas URI is empty")
	}

	k := KASInfo{
		URL: kasurl,
	}

	switch kasurl {
	case kasAu, kasCa, kasUk, kasNz, kasUs:
		k.PublicKey = mockRSAPublicKey1
		k.KID = "r1"
		k.Algorithm = "rsa:2048"
	case kasUsHCS, kasUsSA:
		k.PublicKey = mockRSAPublicKey2
		k.KID = "r2"
		k.Algorithm = "rsa:4096"
	case lessSpecificKas:
		k.PublicKey = mockRSAPublicKey3
		k.KID = "r3"
		k.Algorithm = "rsa:2048"
	default:
		return nil, errors.New("unexpected kas URL: " + kasurl)
	}

	return &k, nil
}

func mockSimpleKasKey(kas, kid string) *policy.SimpleKasKey {
	if kas == "" {
		panic("invalid kas URI")
	}
	if kid == "" {
		panic("invalid kas kid")
	}
	var alg policy.Algorithm
	var pem string
	switch kid {
	case "r0":
		alg = policy.Algorithm_ALGORITHM_RSA_2048
		pem = fakePem
	case "r1":
		alg = policy.Algorithm_ALGORITHM_RSA_2048
		pem = mockRSAPublicKey1
	case "r2":
		alg = policy.Algorithm_ALGORITHM_RSA_4096
		pem = mockRSAPublicKey2
	case "r3":
		alg = policy.Algorithm_ALGORITHM_RSA_2048
		pem = mockRSAPublicKey3
	case "e1":
		alg = policy.Algorithm_ALGORITHM_EC_P256
		pem = mockECPublicKey1
	default:
		panic("invalid kas kid: " + kid)
	}
	return &policy.SimpleKasKey{
		KasUri: kas,
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: alg,
			Kid:       kid,
			Pem:       pem,
		},
	}
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
			p.Grants[0] = mockGrant(kasUk, "r1")
		case "HCS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasUsHCS, "r2")
		case "SI":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasUsSA, "r2")
		}

	case REL.key:
		switch strings.ToUpper(fqn.Value()) {
		case "FVEY":
			p.Grants = make([]*policy.KeyAccessServer, 5)
			p.Grants[0] = mockGrant(kasAu, "r1")
			p.Grants[1] = mockGrant(kasCa, "r1")
			p.Grants[2] = mockGrant(kasUk, "r1")
			p.Grants[3] = mockGrant(kasNz, "r1")
			p.Grants[4] = mockGrant(kasUs, "r1")
		case "AUS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasAu, "r1")
		case "CAN":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasCa, "r1")
		case "GBR":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasUk, "r1")
		case "NZL":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasNz, "r1")
		case "USA":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(kasUs, "r1")
		}
	case CLS.key:
		// defaults only
	case MP.key:
		switch strings.ToLower(fqn.Value()) {
		case "a":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey(evenMoreSpecificKas, "r2")

		case "b":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey(evenMoreSpecificKas, "e1")

		case "c":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey(evenMoreSpecificKas, "r0")

		case "d":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey(evenMoreSpecificKas, "r3")

		case "unspecified":
			// defaults only
		default:
			// defaults only
		}

	case SPECKED.key:
		fallthrough
	case UNSPECKED.key:
		if strings.ToLower(fqn.Value()) == "specked" {
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(evenMoreSpecificKas, "r1")
		}
	case SPKSPECKED.key:
		fallthrough
	case SPKUNSPECKED.key:
		if strings.ToLower(fqn.Value()) == "specked" {
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = mockGrant(evenMoreSpecificKas, "r1")
		}
	case OBLIGATIONATTR.key:
		switch strings.ToLower(fqn.Value()) {
		case "value1":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey(obligationKas, "r3")
		case "value2":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey(obligationKas, "r3")
		case "value3":
			p.KasKeys = make([]*policy.SimpleKasKey, 1)
			p.KasKeys[0] = mockSimpleKasKey("https://d.kas/", "e1")
		}
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
		{"dash", "http://a-b.com/attr/b-c", "http://a-b.com", "b-c"},
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
			assert.Empty(t, a.String())
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
		{"dash", "http://a-b.com/attr/b-c/value/c-d", "http://a-b.com", "b-c", "c-d"},
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
		{"empty name", "http://e/attr//value/0"},
		{"slash name", "http://e/attr///value/0"},
		{"slash in name", "http://0/attr/0/0/value/0"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			a, err := NewAttributeValueFQN(tc.u)
			require.ErrorIs(t, err, ErrInvalid)
			assert.Empty(t, a.String())
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

func policyToStringKeys(policy []AttributeValueFQN) []string {
	s := make([]string, len(policy))
	for i := 0; i < len(s); i++ {
		s[i] = policy[i].key
	}
	return s
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
			grants, err := newGranterFromAttributes(slog.Default(), newKasKeyCache(), v...)
			require.NoError(t, err)
			assert.Len(t, grants.grantTable, tc.size)
			assert.Subset(t, policyToStringKeys(tc.policy), slices.Collect(maps.Keys(grants.grantTable)))
			actualKases := make(map[string]bool)
			for _, g := range grants.grantTable {
				require.NotNil(t, g)
				for _, k := range g.kases {
					actualKases[k] = true
				}
			}
			assert.ElementsMatch(t, tc.kases, slices.Collect(maps.Keys(actualKases)))
		})
	}
}

func TestReasonerConstructAttributeBoolean(t *testing.T) {
	for _, tc := range []struct {
		n                   string
		policy              []AttributeValueFQN
		defaults            []string
		ats, keyed, reduced string
		plan                []keySplitStep
		tpl                 []kaoTpl
	}{
		{
			"one actual with default",
			[]AttributeValueFQN{clsS, rel2can},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/CAN",
			"[DEFAULT]&(https://kas.ca/)",
			"(https://kas.ca/)",
			[]keySplitStep{{kasCa, ""}},
			[]kaoTpl{{kasCa, "", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key}},
		},
		{
			"one defaulted attr",
			[]AttributeValueFQN{clsS},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret",
			"[DEFAULT]",
			"",
			[]keySplitStep{{kasUs, ""}},
			[]kaoTpl{},
		},
		{
			"empty policy",
			[]AttributeValueFQN{},
			[]string{kasUs},
			"∅",
			"",
			"",
			[]keySplitStep{{kasUs, ""}},
			[]kaoTpl{},
		},
		{
			"old school splits",
			[]AttributeValueFQN{},
			[]string{kasAu, kasCa, kasUs},
			"∅",
			"",
			"",
			[]keySplitStep{{kasAu, "1"}, {kasCa, "2"}, {kasUs, "3"}},
			[]kaoTpl{},
		},
		{
			"simple with all three ops",
			[]AttributeValueFQN{clsS, rel2gbr, n2kInt},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
			"[DEFAULT]&(https://kas.uk/)&(https://kas.uk/)",
			"(https://kas.uk/)",
			[]keySplitStep{{kasUk, ""}},
			[]kaoTpl{{kasUk, "", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key}},
		},
		{
			"simple with namespace",
			[]AttributeValueFQN{clsS, spk2uns2uns},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://hasgrants.com/attr/unspecified/value/unspecked",
			"[DEFAULT]&(https://namespace.kas.com/)",
			"(https://namespace.kas.com/)",
			[]keySplitStep{{lessSpecificKas, ""}},
			[]kaoTpl{
				{lessSpecificKas, "", "r3", mockRSAPublicKey3, ocrypto.RSA2048Key},
			},
		},
		{
			"compartments",
			[]AttributeValueFQN{clsS, rel2gbr, rel2usa, n2kHCS, n2kSI},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
			"[DEFAULT]&(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/⋀https://si.kas.us/)",
			"(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/)&(https://si.kas.us/)",
			[]keySplitStep{{kasUk, "1"}, {kasUs, "1"}, {kasUsHCS, "2"}, {kasUsSA, "3"}},
			[]kaoTpl{
				{kasUk, "1", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
				{kasUs, "1", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
				{kasUsHCS, "2", "r2", mockRSAPublicKey2, ocrypto.KeyType("rsa:4096")},
				{kasUsSA, "3", "r2", mockRSAPublicKey2, ocrypto.KeyType("rsa:4096")},
			},
		},
		{
			"compartments - case insensitive",
			[]AttributeValueFQN{messUpV(t, clsS), messUpV(t, rel2gbr), messUpV(t, rel2usa), messUpV(t, n2kHCS), messUpV(t, n2kSI)},
			[]string{kasUs},
			"https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
			"[DEFAULT]&(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/⋀https://si.kas.us/)",
			"(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/)&(https://si.kas.us/)",
			[]keySplitStep{{kasUk, "1"}, {kasUs, "1"}, {kasUsHCS, "2"}, {kasUsSA, "3"}},
			[]kaoTpl{
				{kasUk, "1", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
				{kasUs, "1", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
				{kasUsHCS, "2", "r2", mockRSAPublicKey2, ocrypto.KeyType("rsa:4096")},
				{kasUsSA, "3", "r2", mockRSAPublicKey2, ocrypto.KeyType("rsa:4096")},
			},
		},
		{
			"mappings at attr value",
			[]AttributeValueFQN{mpa, mpb},
			[]string{emptyTerm},
			"https://virtru.com/attr/mapped/value/{a,b}",
			"(https://value.kas.com/⋁https://value.kas.com/)",
			"(https://value.kas.com/)",
			[]keySplitStep{{evenMoreSpecificKas, ""}},
			[]kaoTpl{
				{evenMoreSpecificKas, "1", "e1", mockECPublicKey1, ocrypto.EC256Key},
				{evenMoreSpecificKas, "1", "r2", mockRSAPublicKey2, ocrypto.KeyType("rsa:4096")},
			},
		},
		{
			"mappings at attr definition",
			[]AttributeValueFQN{mpu},
			[]string{emptyTerm},
			"https://virtru.com/attr/mapped/value/unspecified",
			"(https://attr.kas.com/)",
			"(https://attr.kas.com/)",
			[]keySplitStep{{specifiedKas, ""}},
			[]kaoTpl{
				{specifiedKas, "", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
			},
		},
		{
			"mappings all",
			[]AttributeValueFQN{mpa, mpb, mpu},
			[]string{emptyTerm},
			"https://virtru.com/attr/mapped/value/{a,b,unspecified}",
			"(https://value.kas.com/⋁https://value.kas.com/⋁https://attr.kas.com/)",
			"(https://attr.kas.com/⋁https://value.kas.com/)",
			[]keySplitStep{{specifiedKas, "1"}, {evenMoreSpecificKas, "1"}},
			[]kaoTpl{
				{specifiedKas, "1", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
				{evenMoreSpecificKas, "1", "e1", mockECPublicKey1, ocrypto.EC256Key},
				{evenMoreSpecificKas, "1", "r2", mockRSAPublicKey2, ocrypto.KeyType("rsa:4096")},
			},
		},
	} {
		t.Run(tc.n, func(t *testing.T) {
			reasoner, err := newGranterFromAttributes(slog.Default(), newKasKeyCache(), valuesToPolicy(tc.policy...)...)
			require.NoError(t, err)

			reasoner.keyInfoFetcher = &fakeKeyInfoFetcher{}

			actualAB := reasoner.constructAttributeBoolean()
			assert.Equal(t, strings.ToLower(tc.ats), strings.ToLower(actualAB.String()))

			actualKeyed, err := reasoner.insertKeysForAttribute(*actualAB)
			require.NoError(t, err)
			assert.Equal(t, tc.keyed, actualKeyed.String())

			r := actualKeyed.reduce()
			assert.Equal(t, tc.reduced, r.String())

			i := 0
			plan, err := reasoner.plan(tc.defaults, func() string {
				i++
				return strconv.Itoa(i)
			})
			require.NoError(t, err)
			assert.Equal(t, tc.plan, plan)

			j := 0
			tpl, err := reasoner.resolveTemplate(
				t.Context(),
				"",
				func() string {
					j++
					return strconv.Itoa(j)
				})
			require.NoError(t, err)
			assert.Equal(t, tc.tpl, tpl)
		})
	}
}

var listAttributeResp attributes.ListAttributesResponse

type mockAttributesClient struct {
	sdkconnect.AttributesServiceClient
}

func (*mockAttributesClient) ListAttributes(_ context.Context, _ *attributes.ListAttributesRequest) (*attributes.ListAttributesResponse, error) {
	return &listAttributeResp, nil
}

func (*mockAttributesClient) GetAttributeValuesByFqns(_ context.Context, req *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	av := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, v := range req.GetFqns() {
		vfqn, err := NewAttributeValueFQN(v)
		if err != nil {
			return nil, err
		}
		val := mockValueFor(vfqn)
		av[v] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Attribute: val.GetAttribute(),
			Value:     val,
		}
	}

	return &attributes.GetAttributeValuesByFqnsResponse{
		FqnAttributeValues: av,
	}, nil
}

// Tests titles are written in the form [{attr}.{value}] => [{resulting kas boolean exp}]
// where the left hand side is the list of attributes passed in and the right
// is the resulting split steps
// Ex: grant.nogrant means that the attribute has a grant associated with it and the value does not
func TestReasonerSpecificity(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		n        string
		policy   []AttributeValueFQN
		defaults []string
		plan     []keySplitStep
	}{
		{
			"no grants on attr or value should result in split step with provided kas",
			"nogrant.nogrant => default",
			[]AttributeValueFQN{uns2uns},
			[]string{kasUs},
			[]keySplitStep{{kasUs, ""}},
		},
		{
			"no grant on attr, grant on value should result in split step with value kas",
			"nogrant.grant => valueSpecificKas",
			[]AttributeValueFQN{uns2spk},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"grant on attr, no grant on value should result in split step with attr kas",
			"grant.noGrant => attrSpecificKas",
			[]AttributeValueFQN{spk2uns},
			[]string{kasUs},
			[]keySplitStep{{specifiedKas, ""}},
		},
		{
			"grant on attr, grant on value should result in split step with value kas",
			"grant.grant => valueSpecificKas",
			[]AttributeValueFQN{spk2spk},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"two attributes, one with attr and val with grants, other with attr with grant and value without " +
				"should result in two split steps with same splitid, one with value kas and one with attr kas",
			"grant.grant, grant.nogrant => valueSpecificKas || attrSpecificKas",
			[]AttributeValueFQN{spk2spk, spk2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, "1"}, {specifiedKas, "1"}},
		},
		{
			"two attributes, one with attr and val with grants, other with attr with grant and value without " +
				"should result in two split steps with same splitid, one with value kas and one with attr kas",
			"grant.nogrant & grant.grant => valueSpecificKas || attrSpecificKas",
			[]AttributeValueFQN{spk2spk, spk2uns},
			[]string{kasUs},
			[]keySplitStep{{specifiedKas, "1"}, {evenMoreSpecificKas, "1"}},
		},
		{
			"two attributes, one with attr without and val with grant, other with attr and val without " +
				"should result in one split step with value kas",
			"nogrant.grant & nogrant.nogrant => valueSpecificKas",
			[]AttributeValueFQN{uns2spk, uns2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"two attributes, one with attr without and val with grant, other with attr and val without " +
				"should result in one split step with value kas",
			"nogrant.nogrant & nogrant.grant => valueSpecificKas",
			[]AttributeValueFQN{uns2spk, uns2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"two attributes, one with attr and value with grants, other with attr and val without " +
				"should result in one split step with value kas",
			"nogrant.nogrant & grant.grant => valueSpecificKas",
			[]AttributeValueFQN{uns2spk, uns2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
	} {
		t.Run(tc.n, func(t *testing.T) {
			reasoner, err := newGranterFromService(t.Context(), slog.Default(), newKasKeyCache(), &mockAttributesClient{}, tc.policy...)
			require.NoError(t, err)
			i := 0
			plan, err := reasoner.plan(tc.defaults, func() string {
				i++
				return strconv.Itoa(i)
			})
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.plan, plan)
		})
	}
}

// Tests titles are written in the form [{ns}.{attr}.{value}] => [{resulting kas boolean exp}]
// where the left hand side is the list of attributes passed in and the right
// is the resulting split steps
// When the resulting kas exp has || it means the kases should have the same split step
// When the resulting kas exp has && it means the kases should have different split steps
// Ex: grant.grant.nogrant means that both the ns and attribute have
// a grant associated with them and the value does not
func TestReasonerSpecificityWithNamespaces(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		n        string
		policy   []AttributeValueFQN
		defaults []string
		plan     []keySplitStep
	}{
		{
			"no grants on value, attr, namesapce should result in provided kas",
			"nogrant.nogrant.nogrant => default",
			[]AttributeValueFQN{uns2uns},
			[]string{kasUs},
			[]keySplitStep{{kasUs, ""}},
		},
		{
			"grant on namesapce with no grant on attr or value should result in only namesapce specfific kas split step",
			"grant.nogrant.nogrant => nsSpecificKas",
			[]AttributeValueFQN{spk2uns2uns},
			[]string{kasUs},
			[]keySplitStep{{lessSpecificKas, ""}},
		},
		{
			"grant on namespace and value, no attr grant, should result in only value specific kas split step",
			"grant.nogrant.grant => valueSpecificKas",
			[]AttributeValueFQN{spk2uns2spk},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"grant on namespace and attribute, no value grant, should result in attr specific kas split step",
			"grant.grant.nogrant => attrSpecificKas",
			[]AttributeValueFQN{spk2spk2uns},
			[]string{kasUs},
			[]keySplitStep{{specifiedKas, ""}},
		},
		{
			"grant on ns, attr, and value should result in value specific kas split step",
			"grant.grant.grant => valueSpecificKas",
			[]AttributeValueFQN{spk2spk},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"two attributes, same ns and attr with grants, one with value grants and one without" +
				" should result in two split steps with the same splitid, one with attr kas " +
				"and one with value kas",
			"grant.grant.grant & grant.grant.nogrant => valueSpecificKas || attrSpecificKas",
			[]AttributeValueFQN{spk2spk2spk, spk2spk2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, "1"}, {specifiedKas, "1"}},
		},
		{
			"two attributes, same ns and attr with grants, one with value grants and one without" +
				" should result in two split steps with the same splitid, one with attr kas " +
				"and one with value kas",
			"grant.grant.nogrant & grant.grant.grant => valueSpecificKas || attrSpecificKas",
			[]AttributeValueFQN{spk2spk2uns, spk2spk2spk},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, "1"}, {specifiedKas, "1"}},
		},
		{
			"two attributes, same ns, one with attr with grant one without and both no val grants" +
				" should result in two split steps with the diff splitids, one with attr kas " +
				"and one with ns kas",
			"grant.grant.nogrant & grant.nogrant.nogrant => attrSpecificKas && nsSpecificKas",
			[]AttributeValueFQN{spk2spk2uns, spk2uns2uns},
			[]string{kasUs},
			[]keySplitStep{{specifiedKas, "1"}, {lessSpecificKas, "2"}},
		},
		{
			"two attributes, same ns, one with attr with grant one without and both no val grants" +
				" should result in two split steps with the diff splitids, one with attr kas " +
				"and one with ns kas",
			"grant.nogrant.nogrant & grant.grant.nogrant => attrSpecificKas && nsSpecificKas",
			[]AttributeValueFQN{spk2uns2uns, spk2spk2uns},
			[]string{kasUs},
			[]keySplitStep{{lessSpecificKas, "1"}, {specifiedKas, "2"}},
		},
		{
			"two attributes, same ns with grant, same attr without grant, one with val grant one without" +
				" should result in two split steps with the same splitids, one with value kas " +
				"and one with ns kas",
			"grant.nogrant.grant & grant.nogrant.nogrant => valueSpecificKas || nsSpecificKas",
			[]AttributeValueFQN{spk2uns2spk, spk2uns2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, "1"}, {lessSpecificKas, "1"}},
		},
		{
			"two attributes, same ns with grant, same attr without grant, one with val grant one without" +
				" should result in two split steps with the same splitids, one with value kas " +
				"and one with ns kas",
			"grant.nogrant.nogrant & grant.nogrant.grant => valueSpecificKas || nsSpecificKas",
			[]AttributeValueFQN{spk2uns2uns, spk2uns2spk},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, "1"}, {lessSpecificKas, "1"}},
		},
		{
			"two attributes, one with ns with grant and one without, both attrs and vals without grants," +
				" should result in one split step with the ns kas",
			"grant.nogrant.nogrant & nogrant.nogrant.nogrant => nsSpecificKas",
			[]AttributeValueFQN{spk2uns2uns, uns2uns},
			[]string{kasUs},
			[]keySplitStep{{lessSpecificKas, ""}},
		},
		{
			"two attributes, one with ns with grant and one without, both attrs and vals without grants," +
				" should result in one split step with the ns kas",
			"nogrant.nogrant.nogrant & grant.nogrant.nogrant => nsSpecificKas",
			[]AttributeValueFQN{uns2uns, spk2uns2uns},
			[]string{kasUs},
			[]keySplitStep{{lessSpecificKas, ""}},
		},
		{
			"two attributes, one with ns with grant and val with grant, one with ns, attr, and val without grant" +
				" should result in one split step with the value kas",
			"grant.nogrant.grant & nogrant.nogrant.nogrant => valueSpecificKas",
			[]AttributeValueFQN{spk2uns2spk, uns2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
		{
			"two attributes, one with ns with grant and val with grant, one with ns, attr, and val without grant" +
				" should result in one split step with the value kas",
			"grant.grant.grant & nogrant.nogrant.nogrant => valueSpecificKas",
			[]AttributeValueFQN{spk2spk2spk, uns2uns},
			[]string{kasUs},
			[]keySplitStep{{evenMoreSpecificKas, ""}},
		},
	} {
		t.Run((tc.n + "\n" + tc.desc), func(t *testing.T) {
			reasoner, err := newGranterFromService(t.Context(), slog.Default(), newKasKeyCache(), &mockAttributesClient{}, tc.policy...)
			require.NoError(t, err)
			i := 0
			plan, err := reasoner.plan(tc.defaults, func() string {
				i++
				return strconv.Itoa(i)
			})
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.plan, plan)
		})
	}
}
