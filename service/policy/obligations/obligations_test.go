package obligations

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/stretchr/testify/require"
)

const (
	invalidUUID = "invalid-uuid"
	validURI    = "https://example.com/attr/value/1"
	invalidName = "&hello"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_AddObligationTrigger_Request(t *testing.T) {
	validUUID := uuid.NewString()
	validFQN := "https://example.com/attr/value/1"
	invalidFQN := "invalid-fqn"
	validName := "kas"
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
			},
			expectError: false,
		},
		{
			name: "valid fqn and name",
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
			},
			expectError:  true,
			errorMessage: "attribute_value.fqn",
		},
		{
			name: "missing obligation_value",
			req: &obligations.AddObligationTriggerRequest{
				Action:         &common.IdNameIdentifier{Id: validUUID},
				AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "obligation_value",
		},
		{
			name: "missing action",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				AttributeValue:  &common.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "missing attribute_value",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &common.IdFqnIdentifier{Id: validUUID},
				Action:          &common.IdNameIdentifier{Id: validUUID},
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
			},
			expectError:  true,
			errorMessage: "name_format",
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
	testCases := []struct {
		name         string
		req          *obligations.CreateObligationValueRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid with no triggers",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
			},
			expectError: false,
		},
		{
			name: "valid with fqn and no triggers",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Fqn{Fqn: "f.q.n"},
				Value:                "value",
			},
			expectError: false,
		},
		{
			name: "valid with one trigger and ids",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with one trigger and fqns/names",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Name: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Fqn: validURI},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid with multiple triggers",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
					},
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid trigger with invalid action_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: invalidUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
					},
				},
			},
			expectError:  true,
			errorMessage: "action.id",
		},
		{
			name: "invalid trigger with invalid attribute_value_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: invalidUUID},
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value.id",
		},
		{
			name: "invalid trigger with missing action_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
					},
				},
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "invalid trigger with missing attribute_value_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						Action: &common.IdNameIdentifier{Id: validUUID},
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
						AttributeValue: &common.IdFqnIdentifier{Fqn: validURI},
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
					},
					{
						Action:         &common.IdNameIdentifier{Id: validUUID},
						AttributeValue: &common.IdFqnIdentifier{Id: validUUID},
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
						Action: &common.IdNameIdentifier{Id: validUUID},
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
