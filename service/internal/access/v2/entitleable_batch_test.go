package access

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/stretchr/testify/require"
)

func TestEntitleableBatchSplitsSparseMisses(t *testing.T) {
	const definition = "https://scale.example/attr/department"
	const total = 250
	for _, missing := range []int{-1, 0, total - 1, total} {
		t.Run(fmt.Sprintf("missing-%d", missing), func(t *testing.T) {
			fqns := make([]string, total)
			for i := range fqns {
				fqns[i] = fmt.Sprintf("%s/value/%d", definition, i)
			}
			fake := &fakeAttributesClient{respFunc: func(req *attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
				for _, fqn := range req.GetFqns() {
					if missing == total || (missing >= 0 && fqn == fqns[missing]) {
						return nil, connect.NewError(connect.CodeNotFound, errors.New("missing value"))
					}
				}
				resp := &attrs.GetEntitleableAttributesByFqnsResponse{
					Definitions:              map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition{definition: {Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF}},
					FqnEntitleableAttributes: make(map[string]*attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute),
				}
				for _, fqn := range req.GetFqns() {
					resp.FqnEntitleableAttributes[fqn] = &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableAttribute{DefinitionFqn: definition, Value: &attrs.GetEntitleableAttributesByFqnsResponse_EntitleableValue{ValueId: fqn, Fqn: fqn}}
				}
				return resp, nil
			}}
			definitions, _, err := fetchEntitleableAttributes(t.Context(), newSDKWithAttributes(fake), fqns)
			require.NoError(t, err)
			switch missing {
			case -1:
				require.Len(t, fake.requests, 1)
				require.Len(t, definitions[0].GetValues(), total)
			case total:
				require.Empty(t, definitions)
				require.LessOrEqual(t, len(fake.requests), total+8)
			default:
				require.Len(t, definitions, 1)
				require.Len(t, definitions[0].GetValues(), total-1)
				require.LessOrEqual(t, len(fake.requests), 17)
			}
		})
	}
}

func TestEntitleableBatchDoesNotRetryOtherFailures(t *testing.T) {
	expected := connect.NewError(connect.CodeUnavailable, errors.New("policy unavailable"))
	fake := &fakeAttributesClient{respFunc: func(*attrs.GetEntitleableAttributesByFqnsRequest) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
		return nil, expected
	}}
	_, _, err := fetchEntitleableAttributes(t.Context(), newSDKWithAttributes(fake), []string{"https://scale.example/attr/a/value/one", "https://scale.example/attr/a/value/two"})
	require.ErrorIs(t, err, expected)
	require.Len(t, fake.requests, 1)
}
