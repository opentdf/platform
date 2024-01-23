package keyaccessgrants

import (
	"fmt"
	"strings"

	attributes "github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

type GrantService interface {
	ByAttributeValue(attr string) (*KeyAccessGrant, error)
}

type Reasoner struct {
	grantService *GrantService
}

func NewReasoner(grantService *GrantService) *Reasoner {
	return &Reasoner{grantService}
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
