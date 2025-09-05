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
				ObligationValue: &obligations.IdFqnIdentifier{Id: validUUID},
				Action:          &obligations.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Id: validUUID},
			},
			expectError: false,
		},
		{
			name: "valid fqn and name",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Fqn: validFQN},
				Action:          &obligations.IdNameIdentifier{Name: validName},
				AttributeValue:  &obligations.IdFqnIdentifier{Fqn: validFQN},
			},
			expectError: false,
		},
		{
			name: "invalid obligation_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Id: invalidUUID},
				Action:          &obligations.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "obligation_value.id",
		},
		{
			name: "invalid action_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Id: validUUID},
				Action:          &obligations.IdNameIdentifier{Id: invalidUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "action.id",
		},
		{
			name: "invalid attribute_value_id",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Id: validUUID},
				Action:          &obligations.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Id: invalidUUID},
			},
			expectError:  true,
			errorMessage: "attribute_value.id",
		},
		{
			name: "invalid obligation_value_fqn",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Fqn: invalidFQN},
				Action:          &obligations.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Fqn: validFQN},
			},
			expectError:  true,
			errorMessage: "obligation_value.fqn",
		},
		{
			name: "invalid attribute_value_fqn",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Id: validUUID},
				Action:          &obligations.IdNameIdentifier{Id: validUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Fqn: invalidFQN},
			},
			expectError:  true,
			errorMessage: "attribute_value.fqn",
		},
		{
			name: "missing obligation_value",
			req: &obligations.AddObligationTriggerRequest{
				Action:         &obligations.IdNameIdentifier{Id: validUUID},
				AttributeValue: &obligations.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "obligation_value",
		},
		{
			name: "missing action",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Id: validUUID},
				AttributeValue:  &obligations.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "action",
		},
		{
			name: "missing attribute_value",
			req: &obligations.AddObligationTriggerRequest{
				ObligationValue: &obligations.IdFqnIdentifier{Id: validUUID},
				Action:          &obligations.IdNameIdentifier{Id: validUUID},
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
