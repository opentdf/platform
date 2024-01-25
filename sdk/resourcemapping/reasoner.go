package keyaccessgrants

import (
	"fmt"
	"strings"

	attributes "github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

type GrantService interface {
	ByAttribute(attr *attributes.AttributeInstance) (*KeyAccessGrant, error)
}

type Reasoner struct {
	grantService GrantService
}

func NewReasoner(grantService GrantService) *Reasoner {
	return &Reasoner{grantService}
}

type singleAttributeClause struct {
	def    *attributes.AttributeDefinition
	values []attributes.AttributeInstance
}

type attributeBooleanExpression struct {
	must []singleAttributeClause
}

func (r *Reasoner) constructAttributeBoolean(policy ...*attributes.AttributeInstance) (*attributeBooleanExpression, error) {
	prefixes := make(map[string]singleAttributeClause)
	for _, a := range policy {
		p := a.Prefix()
		if clause, ok := prefixes[p]; ok {
			clause.values = append(clause.values, *a)
		} else {
			kag, err := r.grantService.ByAttribute(a)
			if err != nil {
				return nil, err
			}
			prefixes[p] = singleAttributeClause{kag.AttributeDefinition, []attributes.AttributeInstance{*a}}
		}
	}
	must := make([]singleAttributeClause, 0, len(prefixes))[0:0]
	for _, value := range prefixes {
		must = append(must, value)
	}
	return &attributeBooleanExpression{must}, nil
}

type Rule attributes.AttributeDefinition_AttributeRuleType

const (
	ALL_OF       = Rule(attributes.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ALL_OF)
	ANY_OF       = Rule(attributes.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF)
	HIERARCHICAL = Rule(attributes.AttributeDefinition_ATTRIBUTE_RULE_TYPE_HIERARCHICAL)
)

type keyClause struct {
	op     Rule
	values []*KeyAccessServer
}

func (c *keyClause) String() string {
	if len(c.values) == 1 && c.values[0].Url == "DEFAULT" {
		return "[DEFAULT]"
	}
	op := "⋁"
	if c.op == ANY_OF {
		op = "⋀"
	}
	strs := make([]string, len(c.values))
	for i, v := range c.values {
		strs[i] = fmt.Sprintf("%s", v)
	}
	return strings.Join(strs, op)
}

type booleanKeyExpression struct {
	values []keyClause
}
