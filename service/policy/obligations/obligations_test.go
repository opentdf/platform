package obligations

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/stretchr/testify/require"
)

const (
	invalidUUID = "invalid-uuid"
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
	testCases := []struct {
		name         string
		req          *obligations.AddObligationTriggerRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValueId: validUUID,
				ActionId:          validUUID,
				AttributeValueId:  validUUID,
			},
			expectError: false,
		},
		{
			name: "invalid obligation_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValueId: invalidUUID,
				ActionId:          validUUID,
				AttributeValueId:  validUUID,
			},
			expectError:  true,
			errorMessage: "obligation_value_id",
		},
		{
			name: "invalid action_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValueId: validUUID,
				ActionId:          invalidUUID,
				AttributeValueId:  validUUID,
			},
			expectError:  true,
			errorMessage: "action_id",
		},
		{
			name: "invalid attribute_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValueId: validUUID,
				ActionId:          validUUID,
				AttributeValueId:  invalidUUID,
			},
			expectError:  true,
			errorMessage: "attribute_value_id",
		},
		{
			name: "missing obligation_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ActionId:         validUUID,
				AttributeValueId: validUUID,
			},
			expectError:  true,
			errorMessage: "obligation_value_id",
		},
		{
			name: "missing action_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValueId: validUUID,
				AttributeValueId:  validUUID,
			},
			expectError:  true,
			errorMessage: "action_id",
		},
		{
			name: "missing attribute_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValueId: validUUID,
				ActionId:          validUUID,
			},
			expectError:  true,
			errorMessage: "attribute_value_id",
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
			name: "valid with one trigger",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						ActionId:         validUUID,
						AttributeValueId: validUUID,
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
						ActionId:         validUUID,
						AttributeValueId: validUUID,
					},
					{
						ActionId:         validUUID,
						AttributeValueId: validUUID,
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
						ActionId:         invalidUUID,
						AttributeValueId: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "action_id",
		},
		{
			name: "invalid trigger with invalid attribute_value_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						ActionId:         validUUID,
						AttributeValueId: invalidUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value_id",
		},
		{
			name: "invalid trigger with missing action_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						AttributeValueId: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "action_id",
		},
		{
			name: "invalid trigger with missing attribute_value_id",
			req: &obligations.CreateObligationValueRequest{
				ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{Id: validUUID},
				Value:                "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						ActionId: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value_id",
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
						ActionId:         validUUID,
						AttributeValueId: validUUID,
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
						ActionId:         validUUID,
						AttributeValueId: validUUID,
					},
					{
						ActionId:         validUUID,
						AttributeValueId: validUUID,
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
						ActionId:         invalidUUID,
						AttributeValueId: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "action_id",
		},
		{
			name: "invalid trigger with invalid attribute_value_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						ActionId:         validUUID,
						AttributeValueId: invalidUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value_id",
		},
		{
			name: "invalid trigger with missing action_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						AttributeValueId: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "action_id",
		},
		{
			name: "invalid trigger with missing attribute_value_id",
			req: &obligations.UpdateObligationValueRequest{
				Id:    validUUID,
				Value: "value",
				Triggers: []*obligations.ValueTriggerRequest{
					{
						ActionId: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: "attribute_value_id",
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
