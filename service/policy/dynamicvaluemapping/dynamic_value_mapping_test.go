package dynamicvaluemapping

import (
	"testing"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/service/logger"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

const (
	validNamespaceID  = "cf75540a-cd58-4c6c-a502-7108be7a6edd"
	validNamespaceFQN = "https://example.com"
)

func validCreateRequest() *dynamicvaluemapping.CreateDynamicValueMappingRequest {
	return &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: validNamespaceID,
		ValueResolver: &policy.DynamicValueResolver{
			SubjectExternalSelectorValue: ".projects[]",
			Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		},
		Actions: []*policy.Action{{Name: "read"}},
	}
}

func TestCreateDynamicValueMappingRequiresNamespaceRegardlessOfConfig(t *testing.T) {
	for _, namespacedPolicy := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[namespacedPolicy], func(t *testing.T) {
			service := DynamicValueMappingService{
				logger: logger.CreateTestLogger(),
				config: &policyconfig.Config{NamespacedPolicy: namespacedPolicy},
			}

			_, err := service.CreateDynamicValueMapping(t.Context(), connect.NewRequest(validCreateRequest()))

			require.Error(t, err)
			require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
			require.ErrorIs(t, err, errNamespaceRequired)
		})
	}
}

func TestCreateDynamicValueMappingNamespaceValidation(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	tests := []struct {
		name      string
		namespace func(*dynamicvaluemapping.CreateDynamicValueMappingRequest)
		wantError bool
	}{
		{name: "missing", namespace: func(*dynamicvaluemapping.CreateDynamicValueMappingRequest) {}, wantError: true},
		{name: "id", namespace: func(r *dynamicvaluemapping.CreateDynamicValueMappingRequest) { r.NamespaceId = validNamespaceID }},
		{name: "fqn", namespace: func(r *dynamicvaluemapping.CreateDynamicValueMappingRequest) { r.NamespaceFqn = validNamespaceFQN }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := validCreateRequest()
			test.namespace(req)
			err := validator.Validate(req)
			if test.wantError {
				require.Error(t, err)
				require.Contains(t, err.Error(), "message.oneof")
				return
			}
			require.NoError(t, err)
		})
	}
}
