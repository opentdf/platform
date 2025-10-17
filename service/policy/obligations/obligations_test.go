package obligations

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/stretchr/testify/require"
)

const (
	validUUID             = "00000000-0000-0000-0000-000000000000"
	validName             = "drm"
	validValue1           = "watermark"
	validFQN1             = "https://namespace.com/obl/" + validName + "/value/" + validValue1
	validValue2           = "expiration"
	validFQN2             = "https://namespace.com/obl/" + validName + "/value/" + validValue2
	invalidUUID           = "invalid-uuid"
	invalidName           = "invalid name"
	invalidFQN            = "invalid-fqn"
	errMessageUUID        = "string.uuid"
	errMessageURI         = "string.uri"
	errMessageMinItems    = "repeated.min_items"
	errMessageUnique      = "repeated.unique"
	errMessageOneOf       = "message.oneof"
	errMessageRequired    = "required"
	errMessageNameFormat  = "obligation_name_format"
	errMessageValueFormat = "obligation_value_format"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_GetObligation_Succeeds(t *testing.T) {
	req := &obligations.GetObligationRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.GetObligationRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligation_Fails(t *testing.T) {
	req := &obligations.GetObligationRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.GetObligationRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.GetObligationRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_GetObligationsByFQNs_Succeeds(t *testing.T) {
	validFQNs := []string{
		validFQN1,
		validFQN2,
	}
	req := &obligations.GetObligationsByFQNsRequest{
		Fqns: validFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligationsByFQNs_Fails(t *testing.T) {
	emptyFQNs := []string{}
	req := &obligations.GetObligationsByFQNsRequest{
		Fqns: emptyFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageMinItems)

	invalidFQNs := []string{invalidFQN}
	req = &obligations.GetObligationsByFQNsRequest{
		Fqns: invalidFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	duplicateFQNs := []string{validFQN1, validFQN1}
	req = &obligations.GetObligationsByFQNsRequest{
		Fqns: duplicateFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}

func Test_CreateObligation_Succeeds(t *testing.T) {
	req := &obligations.CreateObligationRequest{
		NamespaceId: validUUID,
		Name:        validName,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.CreateObligationRequest{
		NamespaceFqn: validFQN1,
		Name:         validName,
		Values:       []string{validValue1, validValue2},
	}
	v = getValidator()
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_CreateObligation_Fails(t *testing.T) {
	req := &obligations.CreateObligationRequest{
		NamespaceId: invalidUUID,
		Name:        validName,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.CreateObligationRequest{
		NamespaceFqn: invalidFQN,
		Name:         validName,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.CreateObligationRequest{
		NamespaceId: validUUID,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageRequired)

	req = &obligations.CreateObligationRequest{
		NamespaceId:  validUUID,
		NamespaceFqn: validFQN1,
		Name:         validName,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.CreateObligationRequest{
		NamespaceId:  validUUID,
		NamespaceFqn: validFQN1,
		Name:         validName,
		Values:       []string{validValue1, validValue1},
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}

func Test_UpdateObligation_Succeeds(t *testing.T) {
	req := &obligations.UpdateObligationRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.UpdateObligationRequest{
		Id:   validUUID,
		Name: validName,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_UpdateObligation_Fails(t *testing.T) {
	req := &obligations.UpdateObligationRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.UpdateObligationRequest{
		Id:   validUUID,
		Name: invalidName,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageNameFormat)
}

func Test_DeleteObligation_Succeeds(t *testing.T) {
	req := &obligations.DeleteObligationRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.DeleteObligationRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_DeleteObligation_Fails(t *testing.T) {
	req := &obligations.DeleteObligationRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.DeleteObligationRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.DeleteObligationRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.DeleteObligationRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_ListObligations_Succeeds(t *testing.T) {
	req := &obligations.ListObligationsRequest{}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.ListObligationsRequest{
		NamespaceId: validUUID,
	}
	err = v.Validate(req)
	require.NoError(t, err)

	req = &obligations.ListObligationsRequest{
		NamespaceFqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_ListObligations_Fails(t *testing.T) {
	req := &obligations.ListObligationsRequest{
		NamespaceId: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.ListObligationsRequest{
		NamespaceFqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)
}

func Test_GetObligationValue_Succeeds(t *testing.T) {
	req := &obligations.GetObligationValueRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.GetObligationValueRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligationValue_Fails(t *testing.T) {
	req := &obligations.GetObligationValueRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.GetObligationValueRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.GetObligationValueRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.GetObligationValueRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_GetObligationValuesByFQNs_Succeeds(t *testing.T) {
	validFQNs := []string{
		validFQN1,
		validFQN2,
	}
	req := &obligations.GetObligationValuesByFQNsRequest{
		Fqns: validFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligationValuesByFQNs_Fails(t *testing.T) {
	emptyFQNs := []string{}
	req := &obligations.GetObligationValuesByFQNsRequest{
		Fqns: emptyFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageMinItems)

	invalidFQNs := []string{invalidFQN}
	req = &obligations.GetObligationValuesByFQNsRequest{
		Fqns: invalidFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	duplicateFQNs := []string{validFQN1, validFQN1}
	req = &obligations.GetObligationValuesByFQNsRequest{
		Fqns: duplicateFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}

func Test_CreateObligationValue_Succeeds(t *testing.T) {
	req := &obligations.CreateObligationValueRequest{
		ObligationId: validUUID,
		Value:        validValue1,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.CreateObligationValueRequest{
		ObligationFqn: validFQN1,
		Value:         validValue1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_CreateObligationValue_Fails(t *testing.T) {
	req := &obligations.CreateObligationValueRequest{
		ObligationId: invalidUUID,
		Value:        validValue1,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.CreateObligationValueRequest{
		ObligationFqn: invalidFQN,
		Value:         validValue1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.CreateObligationValueRequest{
		ObligationId: validUUID,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageRequired)

	req = &obligations.CreateObligationValueRequest{
		ObligationId:  validUUID,
		ObligationFqn: validFQN1,
		Value:         validValue1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.CreateObligationValueRequest{
		ObligationId: validUUID,
		Value:        invalidName,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageValueFormat)

	req = &obligations.CreateObligationValueRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_UpdateObligationValue_Succeeds(t *testing.T) {
	req := &obligations.UpdateObligationValueRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.UpdateObligationValueRequest{
		Id:    validUUID,
		Value: validValue1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_UpdateObligationValue_Fails(t *testing.T) {
	req := &obligations.UpdateObligationValueRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.UpdateObligationValueRequest{
		Id:    validUUID,
		Value: invalidName,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageValueFormat)
}

func Test_DeleteObligationValue_Succeeds(t *testing.T) {
	req := &obligations.DeleteObligationValueRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.DeleteObligationValueRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_DeleteObligationValue_Fails(t *testing.T) {
	req := &obligations.DeleteObligationValueRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.DeleteObligationValueRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.DeleteObligationValueRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.DeleteObligationValueRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_AddObligationTrigger_Request(t *testing.T) {
	validUUID := uuid.NewString()
	validFQN := "https://example.com/attr/value/1"
	invalidFQN := "invalid-fqn"
	validName := "kas"
	validRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: "client-id",
		},
	}

	testCases := []struct {
		name         string
		req          *obligations.AddObligationTriggerRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError: false,
		},
		{
			name: "valid fqn and name",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Fqn: validFQN},
				Action:          &common.IdNameIdentifier{Name: validName},
				AttributeValue:  &common.IdFqnIdentifier{Fqn: validFQN},
				Context:         validRequestContext,
			},
			expectError: false,
		},
		{
			name: "valid - no context",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Fqn: validFQN},
				Action:          &common.IdNameIdentifier{Name: validName},
				AttributeValue:  &common.IdFqnIdentifier{Fqn: validFQN},
			},
			expectError: false,
		},
		{
			name: "invalid obligation_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: invalidUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "obligation_value.id",
		},
		{
			name: "invalid action_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: invalidUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "action.id",
		},
		{
			name: "invalid attribute_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: invalidUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "attribute_value.id",
		},
		{
			name: "invalid obligation_value_fqn",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Fqn: invalidFQN},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Fqn: validFQN},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "obligation_value.fqn",
		},
		{
			name: "invalid attribute_value_fqn",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Fqn: invalidFQN},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "attribute_value.fqn",
		},
		{
			name: "missing obligation_value",
			req: &obligations.AddObligationTriggerRequest{
				Action:         &common.IdNameIdentifier{Id: validUUID},
				AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
				Context:        validRequestContext,
			},
			expectError:  true,
			errorMessage: "obligation_value",
		},
		{
			name: "missing action",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "missing attribute_value",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "attribute_value",
		},
		{
			name: "two attribute_values - fqn and id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID, Fqn: validFQN},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "attribute_value",
		},
		{
			name: "two obligation_values - fqn and id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID, Fqn: validFQN},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "obligation_value",
		},
		{
			name: "two actions - name and id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID, Name: validName},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "action name not alphanumeric",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Name: invalidName},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         validRequestContext,
			},
			expectError:  true,
			errorMessage: "name_format",
		},
		{
			name: "missing context pep",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         &policy.RequestContext{},
			},
			expectError:  true,
			errorMessage: "context.pep",
		},
		{
			name: "missing pep client_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
				Context:         &policy.RequestContext{Pep: &policy.PolicyEnforcementPoint{}},
			},
			expectError:  true,
			errorMessage: "pep.client_id",
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_RemoveObligationTrigger_Request(t *testing.T) {
	validUUID := uuid.NewString()
	testCases := []struct {
		name         string
		req          *obligations.RemoveObligationTriggerRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid",
			req: &obligations.RemoveObligationTriggerRequest{
				Id: validUUID,
			},
			expectError: false,
		},
		{
			name: "invalid id",
			req: &obligations.RemoveObligationTriggerRequest{
				Id: invalidUUID,
			},
			expectError:  true,
			errorMessage: "id",
		},
		{
			name:         "missing id",
			req:          &obligations.RemoveObligationTriggerRequest{},
			expectError:  true,
			errorMessage: "id",
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_CreateObligationValue_Request(t *testing.T) {
	validUUID := uuid.NewString()
	validRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: "client-id",
		},
	}
	testCases := []struct {
		name         string
		req          *obligations.CreateObligationValueRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid with no triggers",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
			},
			expectError: false,
		},
		{
			name: "valid with fqn and no triggers",
			req: &obligations.CreateObligationValueRequest{
				ObligationFqn: validFQN1,
				Value:         "value",
			},
			expectError: false,
		},
		{
			name: "valid with one trigger and ids",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with one trigger and fqns/names",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Name: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validFQN1},
						Context:        validRequestContext,
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with one trigger - no context",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Name: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validFQN1},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with multiple triggers",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid trigger with invalid action_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: invalidUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "action.id",
		},
		{
			name: "invalid trigger with invalid attribute_value_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: invalidUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value.id",
		},
		{
			name: "invalid trigger with missing action_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "invalid trigger with missing attribute_value_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationId: validUUID,
				Value:        "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:  &common.IdNameIdentifier{Id: validUUID},
						Context: validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value",
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_UpdateObligationValue_Request(t *testing.T) {
	validUUID := uuid.NewString()
	validRequestContext := &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{
			ClientId: "client-id",
		},
	}
	testCases := []struct {
		name         string
		req          *obligations.UpdateObligationValueRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid with no triggers",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
			},
			expectError: false,
		},
		{
			name: "valid with one trigger",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validFQN1},
						Context:        validRequestContext,
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with one trigger - no context",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validFQN1},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with multiple triggers",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid trigger with invalid action_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: invalidUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "action.id",
		},
		{
			name: "invalid trigger with invalid attribute_value_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: invalidUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value.id",
		},
		{
			name: "invalid trigger with missing action_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
						Context:        validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "invalid trigger with missing attribute_value_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:  &common.IdNameIdentifier{Id: validUUID},
						Context: validRequestContext,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value",
		},
		{
			name: "missing context pep",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validFQN1},
						Context:        &policy.RequestContext{},
					},
				},
			},
			expectError:  true,
			errorMessage: "context.pep",
		},
		{
			name: "missing pep client_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validFQN1},
						Context:        &policy.RequestContext{Pep: &policy.PolicyEnforcementPoint{}},
					},
				},
			},
			expectError:  true,
			errorMessage: "pep.client_id",
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_ListObligationTriggers_Request(t *testing.T) {
	validUUID := uuid.NewString()

	testCases := []struct {
		name         string
		req          *obligations.ListObligationTriggersRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid - no filters",
			req:         &obligations.ListObligationTriggersRequest{},
			expectError: false,
		},
		{
			name: "valid - with namespace_id",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceId: validUUID,
			},
			expectError: false,
		},
		{
			name: "valid - with namespace_fqn",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceFqn: validFQN1,
			},
			expectError: false,
		},
		{
			name: "valid - with pagination only",
			req: &obligations.ListObligationTriggersRequest{
				Pagination: &policy.PageRequest{
					Limit:  10,
					Offset: 5,
				},
			},
			expectError: false,
		},
		{
			name: "valid - namespace_id with pagination",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceId: validUUID,
				Pagination: &policy.PageRequest{
					Limit:  20,
					Offset: 0,
				},
			},
			expectError: false,
		},
		{
			name: "valid - namespace_fqn with pagination",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceFqn: validFQN1,
				Pagination: &policy.PageRequest{
					Limit:  15,
					Offset: 10,
				},
			},
			expectError: false,
		},
		{
			name: "invalid namespace_id",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceId: invalidUUID,
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "invalid namespace_fqn",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceFqn: invalidFQN,
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "both namespace_id and namespace_fqn",
			req: &obligations.ListObligationTriggersRequest{
				NamespaceId:  validUUID,
				NamespaceFqn: validFQN1,
			},
			expectError:  true,
			errorMessage: errMessageOneOf,
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMessage)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
