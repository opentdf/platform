package attributes

import (
	"fmt"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

const (
	validName                 = "name"
	validValue1               = "value1"
	validValue2               = "value_2"
	validValue3               = "3_value"
	validUUID                 = "00000000-0000-0000-0000-000000000000"
	errMessageUUID            = "string.uuid"
	errMessageAttrNameFormat  = "attribute_name_format"
	errMessageAttrValueFormat = "attribute_value_format"
	errMessageRequired        = "required"
	errMessageMinLen          = "string.min_len"
	errMessageURI             = "string.uri"
	errRequiredField          = "required_fields"
	errExclusiveFields        = "exclusive_fields"
	errrMessageAttrKey        = "attribute_key"
	errrMessageValueKey       = "value_key"
	errrMessageAttrID         = "attribute_id"
	errrMessageKeyID          = "key_id"
	errrMessageValueID        = "value_id"
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

func TestCreateAttribute_AllowTraversal_Valid_Succeeds(t *testing.T) {
	req := &attributes.CreateAttributeRequest{
		Name:           validName,
		NamespaceId:    validUUID,
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		AllowTraversal: &wrapperspb.BoolValue{Value: true},
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
	require.Contains(t, err.Error(), errMessageAttrNameFormat)
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
		require.Contains(t, err.Error(), errMessageAttrNameFormat)
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
	require.Contains(t, err.Error(), errMessageUUID)
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
	require.Contains(t, err.Error(), errMessageRequired)
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
	require.Contains(t, err.Error(), errMessageRequired)
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

func Test_GetAttributeRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *attributes.GetAttributeRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name: "Invalid AttributeId in Identifier (empty string)",
			req: &attributes.GetAttributeRequest{
				Identifier: &attributes.GetAttributeRequest_AttributeId{
					AttributeId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid AttributeId in Identifier (invalid UUID)",
			req: &attributes.GetAttributeRequest{
				Identifier: &attributes.GetAttributeRequest_AttributeId{
					AttributeId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid Deprecated Id",
			req: &attributes.GetAttributeRequest{
				Id: validUUID,
			},
			expectError: false,
		},
		{
			name: "Invalid Deprecated Id (empty string)",
			req: &attributes.GetAttributeRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errRequiredField,
		},
		{
			name: "Valid AttributeId in Identifier",
			req: &attributes.GetAttributeRequest{
				Identifier: &attributes.GetAttributeRequest_AttributeId{
					AttributeId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid FQN Identifier",
			req: &attributes.GetAttributeRequest{
				Identifier: &attributes.GetAttributeRequest_Fqn{
					Fqn: "https://example.com/valid_fqn",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid FQN Identifier (missing scheme)",
			req: &attributes.GetAttributeRequest{
				Identifier: &attributes.GetAttributeRequest_Fqn{
					Fqn: "example.com/valid_fqn",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Invalid FQN Identifier (empty string)",
			req: &attributes.GetAttributeRequest{
				Identifier: &attributes.GetAttributeRequest_Fqn{
					Fqn: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageMinLen,
		},
		{
			name: "Invalid can't have both Id and Identifier",
			req: &attributes.GetAttributeRequest{
				Id: validUUID,
				Identifier: &attributes.GetAttributeRequest_Fqn{
					Fqn: "https://example.com/valid_fqn",
				},
			},
			expectError:  true,
			errorMessage: errExclusiveFields,
		},
		{
			name:         "Invalid no Id or Identifier",
			req:          &attributes.GetAttributeRequest{},
			expectError:  true,
			errorMessage: errRequiredField,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func TestUpdateAttributeRequest(t *testing.T) {
	req := &attributes.UpdateAttributeRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

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
	require.Contains(t, err.Error(), errMessageUUID)

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
	require.Contains(t, err.Error(), errMessageAttrValueFormat)
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
		require.Contains(t, err.Error(), errMessageAttrValueFormat)
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
	require.Contains(t, err.Error(), errMessageUUID)
}

func TestCreateAttributeValue_ValueMissing_Fails(t *testing.T) {
	req := &attributes.CreateAttributeValueRequest{
		AttributeId: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "value")
	require.Contains(t, err.Error(), errMessageRequired)
}

func Test_GetAttributeValueRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *attributes.GetAttributeValueRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name: "Invalid ValueId in Identifier (empty string)",
			req: &attributes.GetAttributeValueRequest{
				Identifier: &attributes.GetAttributeValueRequest_ValueId{
					ValueId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid ValueId in Identifier (invalid UUID)",
			req: &attributes.GetAttributeValueRequest{
				Identifier: &attributes.GetAttributeValueRequest_ValueId{
					ValueId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid Deprecated Id",
			req: &attributes.GetAttributeValueRequest{
				Id: validUUID,
			},
			expectError: false,
		},
		{
			name: "Invalid Deprecated Id (empty string)",
			req: &attributes.GetAttributeValueRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errRequiredField,
		},
		{
			name: "Valid ValueId in Identifier",
			req: &attributes.GetAttributeValueRequest{
				Identifier: &attributes.GetAttributeValueRequest_ValueId{
					ValueId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid FQN Identifier",
			req: &attributes.GetAttributeValueRequest{
				Identifier: &attributes.GetAttributeValueRequest_Fqn{
					Fqn: "https://example.com/valid_fqn_value",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid FQN Identifier (missing scheme)",
			req: &attributes.GetAttributeValueRequest{
				Identifier: &attributes.GetAttributeValueRequest_Fqn{
					Fqn: "example.com/valid_fqn_value",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Invalid FQN Identifier (empty string)",
			req: &attributes.GetAttributeValueRequest{
				Identifier: &attributes.GetAttributeValueRequest_Fqn{
					Fqn: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageMinLen,
		},
		{
			name: "Invalid can't have both Id and Identifier",
			req: &attributes.GetAttributeValueRequest{
				Id: validUUID,
				Identifier: &attributes.GetAttributeValueRequest_Fqn{
					Fqn: "https://example.com/valid_fqn_value",
				},
			},
			expectError:  true,
			errorMessage: errExclusiveFields,
		},
		{
			name:         "Invalid no Id or Identifier",
			req:          &attributes.GetAttributeValueRequest{},
			expectError:  true,
			errorMessage: errRequiredField,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func TestListAttributeValuesRequest(t *testing.T) {
	req := &attributes.ListAttributeValuesRequest{}
	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

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
	require.Contains(t, err.Error(), errMessageUUID)

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
	require.Contains(t, err.Error(), errMessageUUID)

	req = &attributes.DeactivateAttributeValueRequest{
		Id: validUUID,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func TestGetAttributeValuesByFqns_Valid_Succeeds(t *testing.T) {
	req := &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{
			"any_value",
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestGetAttributeValuesByFqns_FQNsNil_Fails(t *testing.T) {
	req := &attributes.GetAttributeValuesByFqnsRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "fqns")
	require.Contains(t, err.Error(), "[repeated.min_items]")
}

func TestGetAttributeValuesByFqns_FQNsEmpty_Fails(t *testing.T) {
	req := &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{},
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "fqns")
	require.Contains(t, err.Error(), "[repeated.min_items]")
}

func TestGetAttributeValuesByFqns_FQNsOutsideMaxItemsRange_Fails(t *testing.T) {
	outsideRange := 251
	fqns := make([]string, outsideRange)
	for i := 0; i < outsideRange; i++ {
		fqns[i] = fmt.Sprintf("fqn_%d", i)
	}

	req := &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "fqns")
	require.Contains(t, err.Error(), "[repeated.max_items]")
}

// Add tests for validating assigning public key
func Test_AssignKeyToAttribute(t *testing.T) {
	testCases := []struct {
		name         string
		req          *attributes.AssignPublicKeyToAttributeRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Attribute Key (empty)",
			req:          &attributes.AssignPublicKeyToAttributeRequest{},
			expectError:  true,
			errorMessage: errrMessageAttrKey,
		},
		{
			name: "Invalid Attribute Key (empty definition id)",
			req: &attributes.AssignPublicKeyToAttributeRequest{
				AttributeKey: &attributes.AttributeKey{
					KeyId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageAttrID,
		},
		{
			name: "Invalid Attribute Key (empty key id)",
			req: &attributes.AssignPublicKeyToAttributeRequest{
				AttributeKey: &attributes.AttributeKey{
					AttributeId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageKeyID,
		},
		{
			name: "Valid AssignPublicKeyToAttributeRequest",
			req: &attributes.AssignPublicKeyToAttributeRequest{
				AttributeKey: &attributes.AttributeKey{
					AttributeId: validUUID,
					KeyId:       validUUID,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_RemovePublicKeyFromAttribute(t *testing.T) {
	testCases := []struct {
		name         string
		req          *attributes.RemovePublicKeyFromAttributeRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Attribute Key (empty)",
			req:          &attributes.RemovePublicKeyFromAttributeRequest{},
			expectError:  true,
			errorMessage: errrMessageAttrKey,
		},
		{
			name: "Invalid Attribute Key (empty definition id)",
			req: &attributes.RemovePublicKeyFromAttributeRequest{
				AttributeKey: &attributes.AttributeKey{
					KeyId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageAttrID,
		},
		{
			name: "Invalid Attribute Key (empty key id)",
			req: &attributes.RemovePublicKeyFromAttributeRequest{
				AttributeKey: &attributes.AttributeKey{
					AttributeId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageKeyID,
		},
		{
			name: "Valid RemovePublicKeyFromAttributeRequest",
			req: &attributes.RemovePublicKeyFromAttributeRequest{
				AttributeKey: &attributes.AttributeKey{
					AttributeId: validUUID,
					KeyId:       validUUID,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_AssignPublicKeyToValue(t *testing.T) {
	testCases := []struct {
		name         string
		req          *attributes.AssignPublicKeyToValueRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Value Key (empty)",
			req:          &attributes.AssignPublicKeyToValueRequest{},
			expectError:  true,
			errorMessage: errrMessageValueKey,
		},
		{
			name: "Invalid Value Key (empty value id)",
			req: &attributes.AssignPublicKeyToValueRequest{
				ValueKey: &attributes.ValueKey{
					KeyId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageValueID,
		},
		{
			name: "Invalid Value Key (empty key id)",
			req: &attributes.AssignPublicKeyToValueRequest{
				ValueKey: &attributes.ValueKey{
					ValueId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageKeyID,
		},
		{
			name: "Valid AssignPublicKeyToAttributeRequest",
			req: &attributes.AssignPublicKeyToValueRequest{
				ValueKey: &attributes.ValueKey{
					ValueId: validUUID,
					KeyId:   validUUID,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_RemovePublicKeyFromValue(t *testing.T) {
	testCases := []struct {
		name         string
		req          *attributes.RemovePublicKeyFromValueRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Value Key (empty)",
			req:          &attributes.RemovePublicKeyFromValueRequest{},
			expectError:  true,
			errorMessage: errrMessageValueKey,
		},
		{
			name: "Invalid Value Key (empty value id)",
			req: &attributes.RemovePublicKeyFromValueRequest{
				ValueKey: &attributes.ValueKey{
					KeyId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageValueID,
		},
		{
			name: "Invalid Value Key (empty key id)",
			req: &attributes.RemovePublicKeyFromValueRequest{
				ValueKey: &attributes.ValueKey{
					ValueId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errrMessageKeyID,
		},
		{
			name: "Valid AssignPublicKeyToAttributeRequest",
			req: &attributes.RemovePublicKeyFromValueRequest{
				ValueKey: &attributes.ValueKey{
					ValueId: validUUID,
					KeyId:   validUUID,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}
