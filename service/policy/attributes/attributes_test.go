package attributes

import (
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/stretchr/testify/require"
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

var (
	validName   = "name"
	validValue1 = "value1"
	validValue2 = "value_2"
	validValue3 = "3_value"
	validUuid   = "00000000-0000-0000-0000-000000000000"
)

// Create Attributes (definitions)

func TestCreateAttribute_Valid(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUuid,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateAttribute_WithValues_Valid(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUuid,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []string{
			validValue1,
			validValue2,
			validValue3,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateAttribute_NameTooLong(t *testing.T) {
	name := strings.Repeat("a", 254)
	req := &attributes.CreateAttributeRequest{
		Name:        name,
		NamespaceId: validUuid,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "string.max_len")
}

func TestCreateAttribute_NameWithSpace(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        "invalid name",
		NamespaceId: validUuid,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "[attribute_name_format]")
}

func TestCreateAttribute_NameWithNonAlphanumeric(t *testing.T) {
	names := []string{
		"invalid@name",
		"invalid#name",
		"invalid$name",
		"invalid%name",
		"invalid^name",
		"invalid:name",
		"invalid/name",
		"invalid&name",
	}
	for _, name := range names {
		req := &attributes.CreateAttributeRequest{
			Name:        name,
			NamespaceId: validUuid,
			Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		}

		v := getValidator()
		err := v.Validate(req)

		require.Error(t, err)
		require.Contains(t, err.Error(), "[attribute_name_format]")
	}
}

func TestCreateAttribute_NamespaceIdMissing(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name: validName,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "namespace_id")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttribute_RuleMissing(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUuid,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttribute_RuleUnspecified(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUuid,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttribute_RuleInvalid(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUuid,
		// first enum index not mapped to one of 3 defined rules
		Rule: 4,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Contains(t, err.Error(), "enum")
}

func TestCreateAttribute_ValueInvalid(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUuid,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []string{
			"invalid@value",
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "values")
	require.Contains(t, err.Error(), "[string.pattern]")
}

// Create Attribute Values

func TestCreateAttributeValue_Valid(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUuid,
		Value:       validValue1,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateAttributeValue_ValueTooLong(t *testing.T) {
	value := strings.Repeat("a", 254)
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUuid,
		Value:       value,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "string.max_len")
}

func TestCreateAttributeValue_ValueWithSpace(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUuid,
		Value:       "invalid value",
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "[attribute_value_format]")
}

func TestCreateAttributeValue_ValueWithNonAlphanumeric(t *testing.T) {
	values := []string{
		"invalid@value",
		"invalid#value",
		"invalid$value",
		"invalid%value",
		"invalid^value",
		"invalid:value",
		"invalid/value",
		"invalid&value",
	}
	for _, value := range values {
		req := &attributes.CreateAttributeValueRequest{
			AttributeId: validUuid,
			Value:       value,
		}

		v := getValidator()
		err := v.Validate(req)

		require.Error(t, err)
		require.Contains(t, err.Error(), "[attribute_value_format]")
	}
}

func TestCreateAttributeValue_AttributeIdMissing(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		Value: validValue1,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "attribute_id")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttributeValue_ValueMissing(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUuid,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "value")
	require.Contains(t, err.Error(), "[required]")
}
