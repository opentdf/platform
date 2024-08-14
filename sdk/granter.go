package sdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

var (
	ErrInvalid = errors.New("invalid type")
)

// Attribute rule types: operators!
const (
	hierarchy   = "hierarchy"
	allOf       = "allOf"
	anyOf       = "anyOf"
	unspecified = "unspecified"
	emptyTerm   = "DEFAULT"
)

// Represents a which KAS a split with the associated ID should shared with.
type keySplitStep struct {
	KAS, SplitID string
}

// Utility type to represent an FQN for an attribute.
type AttributeNameFQN struct {
	url, key string
}

func NewAttributeNameFQN(u string) (AttributeNameFQN, error) {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/([^/\s]*)$`)
	m := re.FindStringSubmatch(u)
	if len(m) < 3 || len(m[0]) == 0 {
		return AttributeNameFQN{}, fmt.Errorf("%w: attribute regex fail", ErrInvalid)
	}

	_, err := url.PathUnescape(m[2])
	if err != nil {
		return AttributeNameFQN{}, fmt.Errorf("%w: error in attribute name [%s]", ErrInvalid, m[2])
	}
	return AttributeNameFQN{u, strings.ToLower(u)}, nil
}

func (a AttributeNameFQN) String() string {
	return a.url
}

func (a AttributeNameFQN) Select(v string) AttributeValueFQN {
	u := fmt.Sprintf("%s/value/%s", a.url, url.PathEscape(v))
	return AttributeValueFQN{u, strings.ToLower(u)}
}

func (a AttributeNameFQN) Prefix() string {
	return a.url
}

func (a AttributeNameFQN) Authority() string {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/[^/\s]*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic(ErrInvalid)
	}
	return m[1]
}

func (a AttributeNameFQN) Name() string {
	re := regexp.MustCompile(`^https?://[\w./-]+/attr/([^/\s]*)$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic("invalid attribute")
	}
	v, err := url.PathUnescape(m[1])
	if err != nil {
		panic(ErrInvalid)
	}
	return v
}

// Utility type to represent an FQN for an attribute value.
type AttributeValueFQN struct {
	url, key string
}

func NewAttributeValueFQN(u string) (AttributeValueFQN, error) {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/(\S*)/value/(\S*)$`)
	m := re.FindStringSubmatch(u)
	if len(m) < 4 || len(m[0]) == 0 {
		return AttributeValueFQN{}, fmt.Errorf("%w: attribute regex fail for [%s]", ErrInvalid, u)
	}

	_, err := url.PathUnescape(m[2])
	if err != nil {
		return AttributeValueFQN{}, fmt.Errorf("%w: error in attribute name [%s]", ErrInvalid, m[2])
	}
	_, err = url.PathUnescape(m[3])
	if err != nil {
		return AttributeValueFQN{}, fmt.Errorf("%w: error in attribute value [%s]", ErrInvalid, m[3])
	}

	return AttributeValueFQN{u, strings.ToLower(u)}, nil
}

func (a AttributeValueFQN) String() string {
	return a.url
}

func (a AttributeValueFQN) Authority() string {
	re := regexp.MustCompile(`^(https?://[\w./-]+)/attr/\S*/value/\S*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic(ErrInvalid)
	}
	return m[1]
}

func (a AttributeValueFQN) Prefix() AttributeNameFQN {
	re := regexp.MustCompile(`^(https?://[\w./-]+/attr/\S*)/value/\S*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic(ErrInvalid)
	}
	p, err := NewAttributeNameFQN(m[1])
	if err != nil {
		panic(ErrInvalid)
	}
	return p
}

func (a AttributeValueFQN) Value() string {
	re := regexp.MustCompile(`^https?://[\w./-]+/attr/\S*/value/(\S*)$`)
	m := re.FindStringSubmatch(a.String())
	if m == nil {
		panic(ErrInvalid)
	}
	v, err := url.PathUnescape(m[1])
	if err != nil {
		panic(ErrInvalid)
	}
	return v
}

func (a AttributeValueFQN) Name() string {
	re := regexp.MustCompile(`^https?://[\w./-]+/attr/(\S*)/value/\S*$`)
	m := re.FindStringSubmatch(a.url)
	if m == nil {
		panic("invalid attributeInstance")
	}
	v, err := url.PathUnescape(m[1])
	if err != nil {
		panic("invalid attributeInstance")
	}
	return v
}

// Structure capable of generating a split plan from a given set of data tags.
type granter struct {
	policy []AttributeValueFQN
	grants map[string]*keyAccessGrant
}

type keyAccessGrant struct {
	attr  *policy.Attribute
	kases []string
}

func (r granter) addGrant(fqn AttributeValueFQN, kas string, attr *policy.Attribute) {
	if _, ok := r.grants[fqn.key]; ok {
		r.grants[fqn.key].kases = append(r.grants[fqn.key].kases, kas)
	} else {
		r.grants[fqn.key] = &keyAccessGrant{attr, []string{kas}}
	}
}

func (r granter) addAllGrants(fqn AttributeValueFQN, gs []*policy.KeyAccessServer, attr *policy.Attribute) {
	for _, g := range gs {
		if g != nil {
			r.addGrant(fqn, g.GetUri(), attr)
		}
	}
	if len(gs) == 0 {
		if _, ok := r.grants[fqn.key]; !ok {
			r.grants[fqn.key] = &keyAccessGrant{attr, []string{}}
		}
	}
}

func (r granter) byAttribute(fqn AttributeValueFQN) *keyAccessGrant {
	return r.grants[fqn.key]
}

// Gets a list of directory of KAS grants for a list of attribute FQNs
func newGranterFromService(ctx context.Context, keyCache *kasKeyCache, as attributes.AttributesServiceClient, fqns ...AttributeValueFQN) (granter, error) {
	fqnsStr := make([]string, len(fqns))
	for i, v := range fqns {
		fqnsStr[i] = v.String()
	}

	av, err :=
		as.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{
			Fqns: fqnsStr,
			WithValue: &policy.AttributeValueSelector{
				WithKeyAccessGrants: true,
			},
		})
	if err != nil {
		return granter{}, err
	}

	grants := granter{
		policy: fqns,
		grants: make(map[string]*keyAccessGrant),
	}
	for fqnstr, pair := range av.GetFqnAttributeValues() {
		fqn, err := NewAttributeValueFQN(fqnstr)
		if err != nil {
			return grants, err
		}
		def := pair.GetAttribute()
		if def != nil {
			grants.addAllGrants(fqn, def.GetGrants(), def)
			storeKeysToCache(def.GetGrants(), keyCache)
		}
		v := pair.GetValue()
		if v != nil {
			grants.addAllGrants(fqn, v.GetGrants(), def)
			storeKeysToCache(v.GetGrants(), keyCache)
		}
	}

	return grants, nil
}

func storeKeysToCache(kases []*policy.KeyAccessServer, c *kasKeyCache) {
	for _, kas := range kases {
		if kas.GetPublicKey() == nil || kas.GetPublicKey().GetCached() == nil || kas.GetPublicKey().GetCached().GetKeys() == nil || len(kas.GetPublicKey().GetCached().GetKeys()) == 0 {
			slog.Debug("no cached key in policy service", "kas", kas.GetUri())
			continue
		}
		for _, ki := range kas.GetPublicKey().GetCached().GetKeys() {
			c.store(KASInfo{
				URL:       kas.GetUri(),
				KID:       ki.GetKid(),
				Algorithm: ki.GetAlg(),
				PublicKey: ki.GetPem(),
			})
		}
	}
}

// Given a policy (list of data attributes or tags),
// get a set of grants from attribute values to KASes.
// Unlike `NewGranterFromService`, this works offline.
func newGranterFromAttributes(attrs ...*policy.Value) (granter, error) {
	grants := granter{
		grants: make(map[string]*keyAccessGrant),
		policy: make([]AttributeValueFQN, len(attrs)),
	}
	for i, v := range attrs {
		fqn, err := NewAttributeValueFQN(v.GetFqn())
		if err != nil {
			return grants, err
		}
		grants.policy[i] = fqn
		def := v.GetAttribute()
		if def == nil {
			return granter{}, fmt.Errorf("no associated definition with value [%s]", fqn)
		}
		grants.addAllGrants(fqn, def.GetGrants(), def)
		grants.addAllGrants(fqn, v.GetGrants(), def)
	}

	return grants, nil
}

type singleAttributeClause struct {
	def    *policy.Attribute
	values []AttributeValueFQN
}

type attributeBooleanExpression struct {
	must []singleAttributeClause
}

func (e attributeBooleanExpression) String() string {
	if len(e.must) == 0 {
		return "∅"
	}
	var sb strings.Builder
	for i, clause := range e.must {
		if i > 0 {
			sb.WriteString("&")
		}
		switch len(clause.values) {
		case 0:
			sb.WriteString(clause.def.GetFqn())
		case 1:
			sb.WriteString(clause.values[0].String())
		default:
			sb.WriteString(clause.def.GetFqn())
			sb.WriteString("/value/{")
			for j, v := range clause.values {
				if j > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(v.Value())
			}
			sb.WriteString("}")
		}
	}
	return sb.String()
}

func (r granter) plan(defaultKas []string, genSplitID func() string) ([]keySplitStep, error) {
	b := r.constructAttributeBoolean()
	k, err := r.insertKeysForAttribute(*b)
	if err != nil {
		return nil, err
	}

	k = k.reduce()
	l := k.Len()
	if l == 0 {
		// default behavior: split key accross all default kases
		switch len(defaultKas) {
		case 0:
			return nil, fmt.Errorf("no default KAS specified; required for grantless plans")
		case 1:
			return []keySplitStep{{KAS: defaultKas[0]}}, nil
		default:
			p := make([]keySplitStep, 0, len(defaultKas))
			for _, kas := range defaultKas {
				p = append(p, keySplitStep{KAS: kas, SplitID: genSplitID()})
			}
			return p, nil
		}
	}
	p := make([]keySplitStep, 0, l)
	for _, v := range k.values {
		splitID := ""
		if l > 1 {
			splitID = genSplitID()
		}
		for _, o := range v.values {
			p = append(p, keySplitStep{KAS: o.kas, SplitID: splitID})
		}
	}
	return p, nil
}

func (r granter) constructAttributeBoolean() *attributeBooleanExpression {
	prefixes := make(map[string]*singleAttributeClause)
	sortedPrefixes := make([]string, 0)
	for _, aP := range r.policy {
		a := aP
		p := strings.ToLower(a.Prefix().String())
		if clause, ok := prefixes[p]; ok {
			clause.values = append(clause.values, a)
		} else if kag := r.byAttribute(a); kag != nil {
			prefixes[p] = &singleAttributeClause{kag.attr, []AttributeValueFQN{a}}
			sortedPrefixes = append(sortedPrefixes, p)
		}
	}
	must := make([]singleAttributeClause, 0, len(prefixes))[0:0]
	for _, p := range sortedPrefixes {
		must = append(must, *prefixes[p])
	}
	return &attributeBooleanExpression{must}
}

type publicKeyInfo struct {
	kas string
}

type keyClause struct {
	operator string
	values   []publicKeyInfo
}

func (e keyClause) String() string {
	if len(e.values) == 1 && e.values[0].kas == emptyTerm {
		return "[" + emptyTerm + "]"
	}
	if len(e.values) == 1 {
		return "(" + e.values[0].kas + ")"
	}
	var sb strings.Builder
	sb.WriteString("(")
	op := "⋀"
	if e.operator == anyOf {
		op = "⋁"
	}
	for i, v := range e.values {
		if i > 0 {
			sb.WriteString(op)
		}
		sb.WriteString(v.kas)
	}
	sb.WriteString(")")
	return sb.String()
}

type booleanKeyExpression struct {
	values []keyClause
}

func (e booleanKeyExpression) String() string {
	var sb strings.Builder
	for i, v := range e.values {
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(v.String())
	}
	return sb.String()
}

func ruleToOperator(e policy.AttributeRuleTypeEnum) string {
	switch e {
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
		return allOf
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
		return anyOf
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
		return hierarchy
	case policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
		return unspecified
	}
	return ""
}

func (r *granter) insertKeysForAttribute(e attributeBooleanExpression) (booleanKeyExpression, error) {
	kcs := make([]keyClause, 0, len(e.must))
	for _, clause := range e.must {
		kcv := make([]publicKeyInfo, 0, len(clause.values))
		for _, term := range clause.values {
			grant := r.byAttribute(term)
			if grant == nil {
				return booleanKeyExpression{}, fmt.Errorf("no defintion or grant found for [%s]", term)
			}
			kases := grant.kases
			if len(kases) == 0 {
				kases = []string{emptyTerm}
			}
			for _, kas := range kases {
				kcv = append(kcv, publicKeyInfo{kas})
			}
		}
		op := ruleToOperator(clause.def.GetRule())
		if op == unspecified {
			slog.Warn("unknown attribute rule type", "rule", clause)
		}
		kc := keyClause{
			operator: op,
			values:   kcv,
		}
		kcs = append(kcs, kc)
	}
	return booleanKeyExpression{
		values: kcs,
	}, nil
}

// remove duplicates, sort a set of strings
func sortedNoDupes(l []publicKeyInfo) disjunction {
	set := map[string]bool{}
	list := make([]string, 0)
	for _, e := range l {
		kas := e.kas
		if kas != emptyTerm && !set[kas] {
			set[kas] = true
			list = append(list, kas)
		}
	}
	sort.Strings(list)
	return list
}

type disjunction []string

func (l disjunction) Less(r disjunction) bool {
	m := min(len(l), len(r))
	for i := 1; i <= m; i++ {
		if l[i] < r[i] {
			return true
		}
		if l[i] > r[i] {
			return false
		}
	}
	return len(l) < len(r)
}

func (l disjunction) Equal(r disjunction) bool {
	if len(l) != len(r) {
		return false
	}
	for i, v := range l {
		if v != r[i] {
			return false
		}
	}
	return true
}

func within(l []disjunction, e disjunction) bool {
	for _, v := range l {
		if e.Equal(v) {
			return true
		}
	}
	return false
}

func (e booleanKeyExpression) Len() int {
	c := 0
	for _, v := range e.values {
		c += len(v.values)
	}
	return c
}

func (e booleanKeyExpression) reduce() booleanKeyExpression {
	var conjunction []disjunction
	for _, v := range e.values {
		switch v.operator {
		case anyOf:
			terms := sortedNoDupes(v.values)
			if len(terms) > 0 && !within(conjunction, terms) {
				conjunction = append(conjunction, terms)
			}
		default:
			for _, k := range v.values {
				if k.kas == emptyTerm {
					continue
				}
				terms := []string{k.kas}
				if !within(conjunction, terms) {
					conjunction = append(conjunction, terms)
				}
			}
		}
	}
	if len(conjunction) == 0 {
		return booleanKeyExpression{}
	}
	values := make([]keyClause, len(conjunction))
	for i, d := range conjunction {
		pki := make([]publicKeyInfo, len(d))
		for j, k := range d {
			pki[j] = publicKeyInfo{k}
		}
		values[i] = keyClause{
			operator: anyOf,
			values:   pki,
		}
	}
	return booleanKeyExpression{values}
}
