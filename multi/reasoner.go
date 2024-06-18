package multi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Public Key Algorithms
const (
	rsa_2048     = "rsa:2048"
	ec_secp256r1 = "ec_secp256r1"
)

// PublicKeyResponse objects
type PublicKeyResponse struct {
	kid       string
	publicKey string
}

// Attribute rule types
const (
	hierarchy = "hierarchy"
	anyOf     = "anyOf"
	allOf     = "allOf"
)

type AttributeDefinition struct {
	authority string
	name      string
	order     []string
	rule      string
}

type AttributeInstance struct {
	authority string
	name      string
	value     string
}

type EncryptionMapping struct {
	kas    string
	grants []KeyAccessGrant
}

type KeyAccessGrant struct {
	attr  *AttributeDefinition
	kases []string
}

func (t *AttributeDefinition) UnmarshalJSON(b []byte) error {
	var a AttributeDefinition
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	if !strings.HasSuffix(a.authority, "/") {
		return errors.New(fmt.Sprintf("invalid authority [%s]", a.authority))
	}
	switch strings.ToLower(a.rule) {
	case "allof":
		a.rule = allOf
	case "anyof":
		a.rule = anyOf
	case "hierarchy":
		a.rule = hierarchy
	default:
		a.rule = ""
	}
	*t = a

	return nil
}

func fromURL(u string) (*AttributeInstance, error) {
	re := regexp.MustCompile(`^(https?://[\w./]+)/attr/(\S*)/value/(\S*)$`)
	m := re.FindStringSubmatch(u)
	if len(m[0]) == 0 {
		return nil, errors.New("invalid attribute url")
	}

	k, err := url.PathUnescape(m[2])
	if err != nil {
		return nil, errors.New("invalid attribute url")
	}
	v, err := url.PathUnescape(m[3])
	if err != nil {
		return nil, errors.New("invalid attribute url")
	}

	return &AttributeInstance{m[1], k, v}, nil
}

func (a *AttributeDefinition) Prefix() string {
	return fmt.Sprintf("%sattr/%s", a.authority, url.PathEscape(a.name))
}

func (a AttributeDefinition) Select(v string) (*AttributeInstance, error) {
	for _, e := range a.order {
		if e == v {
			return &AttributeInstance{a.authority, a.name, v}, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("invalid attribute value: [%s] not within %v", v, a.order))
}

func (a *AttributeInstance) Prefix() string {
	return fmt.Sprintf("%sattr/%s", a.authority, url.PathEscape(a.name))
}

func (a AttributeInstance) String() string {
	return fmt.Sprintf("%sattr/%s/value/%s", a.authority, url.PathEscape(a.name), url.PathEscape(a.value))
}

type AttributeService struct {
	dict  map[string]*AttributeDefinition
	names map[string]*AttributeDefinition
}

func (s *AttributeService) Put(ad *AttributeDefinition) error {
	if s.dict == nil {
		s.dict = make(map[string]*AttributeDefinition)
	}
	if s.names == nil {
		s.names = make(map[string]*AttributeDefinition)
	}
	prefix := ad.Prefix()
	if _, exists := s.dict[prefix]; exists {
		return errors.New(fmt.Sprintf("ad prefix already found [%s]", prefix))
	}
	if _, exists := s.names[ad.name]; exists {
		return errors.New(fmt.Sprintf("ad name already found [%s]", ad.name))
	}
	s.dict[prefix] = ad
	s.names[ad.name] = ad
	return nil
}

// Given an attrtibute without a value (everything before /value/...), get the definition
func (s *AttributeService) Get(prefix string) (*AttributeDefinition, error) {
	ad, exists := s.dict[prefix]
	if !exists {
		return nil, errors.New(fmt.Sprintf("[404] Unknown attribute type: [%s], not in [%v]", prefix, s.dict))
	}
	return ad, nil
}

type ConfigurationService struct {
	by_kas    map[string]*EncryptionMapping
	by_attr   map[string][]string
	by_prefix map[string][]*EncryptionMapping
}

func NewConfigurationService() ConfigurationService {
	var s ConfigurationService
	s.by_attr = make(map[string][]string)
	s.by_kas = make(map[string]*EncryptionMapping)
	s.by_prefix = make(map[string][]*EncryptionMapping)
	return s
}

func (s *ConfigurationService) Put(em *EncryptionMapping) error {
	for _, grant := range em.grants {
		for _, v := range grant.kases {
			a := fmt.Sprintf("%s/value/%s", grant.attr, url.PathEscape(v))
			s.by_attr[a] = append(s.by_attr[a], em.kas)
		}
		prefix := grant.attr.Prefix()
		s.by_prefix[prefix] = append(s.by_prefix[prefix], em)
	}
	s.by_kas[em.kas] = em
	return nil
}

// Gets all kases implied by a given attribute instance
func (s *ConfigurationService) ForAttrInstance(fullAttr string) []string {
	return s.by_attr[fullAttr]
}

// Gets all mapping associated with a given attribute definition (auth+name)
func (s *ConfigurationService) ForAttr(prefix string) []*EncryptionMapping {
	return s.by_prefix[prefix]
}

type GrantService interface {
	// Lookup a grant for a given attribute
	ByAttribute(attr *AttributeInstance) (*KeyAccessGrant, error)
}

type Reasoner struct {
	grantService GrantService
}

func NewReasoner(grantService GrantService) *Reasoner {
	return &Reasoner{grantService}
}

type singleAttributeClause struct {
	def    *AttributeDefinition
	values []AttributeInstance
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
			sb.WriteString(clause.def.Prefix())
		case 1:
			sb.WriteString(clause.values[0].String())
		default:
			sb.WriteString(clause.def.Prefix())
			sb.WriteString("/value/{")
			for j, v := range clause.values {
				if j > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(v.value)
			}
			sb.WriteString("}")
		}
	}
	return sb.String()
}

func (r *Reasoner) constructAttributeBoolean(policy ...*AttributeInstance) (*attributeBooleanExpression, error) {
	prefixes := make(map[string]*singleAttributeClause)
	sortedPrefixes := make([]string, 0)
	for _, aP := range policy {
		a := aP
		p := a.Prefix()
		if clause, ok := prefixes[p]; ok {
			clause.values = append(clause.values, *a)
		} else {
			kag, err := r.grantService.ByAttribute(a)
			if err != nil {
				return nil, err
			}
			prefixes[p] = &singleAttributeClause{kag.attr, []AttributeInstance{*a}}
			sortedPrefixes = append(sortedPrefixes, p)
		}
	}
	must := make([]singleAttributeClause, 0, len(prefixes))[0:0]
	for _, p := range sortedPrefixes {
		must = append(must, *prefixes[p])
	}
	return &attributeBooleanExpression{must}, nil
}

type publicKeyInfo struct {
	kas string
}

type keyClause struct {
	operator string
	values   []publicKeyInfo
}

func (e keyClause) String() string {
	if len(e.values) == 1 && e.values[0].kas == "DEFAULT" {
		return "[DEFAULT]"
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

func (r *Reasoner) insertKeysForAttribute(e attributeBooleanExpression) (*booleanKeyExpression, error) {
	kcs := make([]keyClause, 0, len(e.must))
	for _, clause := range e.must {
		kcv := make([]publicKeyInfo, 0, len(clause.values))
		for _, term := range clause.values {
			grant, err := r.grantService.ByAttribute(&term)
			if err != nil {
				return nil, err
			}
			kases := grant.kases
			if len(kases) == 0 {
				kases = []string{"DEFAULT"}
			}
			for _, kas := range kases {
				kcv = append(kcv, publicKeyInfo{kas})
			}
		}
		kc := keyClause{
			operator: clause.def.rule,
			values:   kcv,
		}
		kcs = append(kcs, kc)
	}
	return &booleanKeyExpression{
		values: kcs,
	}, nil
}

// remove duplicates, sort a set of strings
func sortedNoDupes(l []publicKeyInfo) disjunction {
	set := map[string]bool{}
	list := make([]string, 0, 2)
	for _, e := range l {
		kas := e.kas
		if kas == "DEFAULT" {
			// skip
		} else if !set[kas] {
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

func (e booleanKeyExpression) reduce() booleanKeyExpression {
	var conjunction []disjunction
	for _, v := range e.values {
		switch v.operator {
		case anyOf:
			disjunction := sortedNoDupes(v.values)
			if len(disjunction) == 0 {
				// default clause
			} else if within(conjunction, disjunction) {
				// already present disjunction clause
			} else {
				conjunction = append(conjunction, disjunction)
			}
		default:
			for _, k := range v.values {
				if k.kas == "DEFAULT" {
					continue
				}
				disjunction := []string{k.kas}
				if !within(conjunction, disjunction) {
					conjunction = append(conjunction, disjunction)
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

// type Rule attributes.AttributeRuleTypeEnum

// type keyClause struct {
// 	op     Rule
// 	values []*KeyAccessServer
// }

// func (c *keyClause) String() string {
// 	if len(c.values) == 1 && c.values[0].Url == "DEFAULT" {
// 		return "[DEFAULT]"
// 	}
// 	op := "⋁"
// 	if c.op == ANY_OF {
// 		op = "⋀"
// 	}
// 	strs := make([]string, len(c.values))
// 	for i, v := range c.values {
// 		strs[i] = fmt.Sprintf("%s", v)
// 	}
// 	return strings.Join(strs, op)
// }

// type booleanKeyExpression struct {
// 	values []keyClause
// }
