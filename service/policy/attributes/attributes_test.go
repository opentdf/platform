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
	validUUID   = "00000000-0000-0000-0000-000000000000"
)

// Create Attributes (definitions)

func TestCreateAttribute_Valid_Succeeds(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUUID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateAttribute_WithValues_Valid_Succeeds(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUUID,
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

func TestCreateAttribute_NameTooLong_Fails(t *testing.T) {
	name := strings.Repeat("a", 254)
	req := &attributes.CreateAttributeRequest{
		Name:        name,
		NamespaceId: validUUID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "string.max_len")
}

func TestCreateAttribute_NameWithSpace_Fails(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        "invalid name",
		NamespaceId: validUUID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "[attribute_name_format]")
}

func TestCreateAttribute_NameWithNonAlphanumeric_Fails(t *testing.T) {
	// test a couple of the likely most common invalid characters, but knowing the set is much larger
	names := []string{
		"invalid@name",
		"invalid:name",
		"invalid/name",
	}
	for _, name := range names {
		req := &attributes.CreateAttributeRequest{
			Name:        name,
			NamespaceId: validUUID,
			Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		}

		v := getValidator()
		err := v.Validate(req)

		require.Error(t, err)
		require.Contains(t, err.Error(), "[attribute_name_format]")
	}
}

func TestCreateAttribute_NamespaceIdMissing_Fails(t *testing.T) {
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

func TestCreateAttribute_RuleMissing_Fails(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttribute_RuleUnspecified_Fails(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUUID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttribute_RuleInvalid_Fails(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUUID,
		// first enum index not mapped to one of 3 defined rules
		Rule: 4,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Contains(t, err.Error(), "enum")
}

func TestCreateAttribute_ValueInvalid_Fails(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:        validName,
		NamespaceId: validUUID,
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

func TestCreateAttributeValue_Valid_Succeeds(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUUID,
		Value:       validValue1,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateAttributeValue_ValueTooLong_Fails(t *testing.T) {
	value := strings.Repeat("a", 254)
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUUID,
		Value:       value,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "string.max_len")
}

func TestCreateAttributeValue_ValueWithSpace_Fails(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUUID,
		Value:       "invalid value",
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "[attribute_value_format]")
}

func TestCreateAttributeValue_ValueWithNonAlphanumeric_Fails(t *testing.T) {
	// test a couple of the likely most common invalid characters, but knowing the set is much larger
	values := []string{
		"invalid@value",
		"invalid:value",
		"invalid/value",
	}
	for _, value := range values {
		req := &attributes.CreateAttributeValueRequest{
			AttributeId: validUUID,
			Value:       value,
		}

		v := getValidator()
		err := v.Validate(req)

		require.Error(t, err)
		require.Contains(t, err.Error(), "[attribute_value_format]")
	}
}

func TestCreateAttributeValue_AttributeIdMissing_Fails(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		Value: validValue1,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "attribute_id")
	require.Contains(t, err.Error(), "[required]")
}

func TestCreateAttributeValue_ValueMissing_Fails(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "value")
	require.Contains(t, err.Error(), "[required]")
}
