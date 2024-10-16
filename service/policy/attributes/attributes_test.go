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
	require.Contains(t, err.Error(), "[string.uuid_empty]")
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

func TestAttributeKeyAccessServer_Succeeds(t *testing.T) {
	validAttrKAS := &attributes.AttributeKeyAccessServer{
		AttributeId:       validUUID,
		KeyAccessServerId: validUUID,
	}

	err := getValidator().Validate(validAttrKAS)
	require.NoError(t, err)
}

func TestAttributeKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		attrID string
		kasID  string
	}{
		{
			"",
			validUUID,
		},
		{
			validUUID,
			"",
		},
		{
			"",
			"",
		},
		{},
	}

	for _, test := range bad {
		invalidAttrKAS := &attributes.AttributeKeyAccessServer{
			AttributeId:       test.attrID,
			KeyAccessServerId: test.kasID,
		}
		err := getValidator().Validate(invalidAttrKAS)
		require.Error(t, err)
		require.Contains(t, err.Error(), "string.uuid")
	}
}

func TestGetAttributeRequest(t *testing.T) {
	req := &attributes.GetAttributeRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.GetAttributeRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func TestUpdateAttributeRequest(t *testing.T) {
	req := &attributes.UpdateAttributeRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.UpdateAttributeRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func TestDeactivateAttributeRequest(t *testing.T) {
	req := &attributes.DeactivateAttributeRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.DeactivateAttributeRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
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
	require.Contains(t, err.Error(), "[string.uuid_empty]")
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

func TestValueKeyAccessServer_Succeeds(t *testing.T) {
	validValueKAS := &attributes.ValueKeyAccessServer{
		ValueId:           validUUID,
		KeyAccessServerId: validUUID,
	}

	err := getValidator().Validate(validValueKAS)
	require.NoError(t, err)
}

func TestValueKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		valID string
		kasID string
	}{
		{
			"",
			validUUID,
		},
		{
			validUUID,
			"",
		},
		{
			"",
			"",
		},
		{},
	}

	for _, test := range bad {
		invalidValKAS := &attributes.ValueKeyAccessServer{
			ValueId:           test.valID,
			KeyAccessServerId: test.kasID,
		}
		err := getValidator().Validate(invalidValKAS)
		require.Error(t, err)
		require.Contains(t, err.Error(), "string.uuid")
	}
}

func TestGetAttributeValueRequest(t *testing.T) {
	req := &attributes.GetAttributeValueRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.GetAttributeValueRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func TestListAttributeValuesRequest(t *testing.T) {
	req := &attributes.ListAttributeValuesRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.ListAttributeValuesRequest{
		AttributeId: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func TestUpdateAttributeValueRequest(t *testing.T) {
	req := &attributes.UpdateAttributeValueRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.UpdateAttributeValueRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func TestDeactivateAttributeValueRequest(t *testing.T) {
	req := &attributes.DeactivateAttributeValueRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.uuid")

	req = &attributes.DeactivateAttributeValueRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}
