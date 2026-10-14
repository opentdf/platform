package subjectmappingbuiltin

import (
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func TestIndexedSelectorsPreserveConditionSemantics(t *testing.T) {
	flattened, err := flattening.Flatten(map[string]interface{}{"roles": []interface{}{"reader", "admin"}, "active": true})
	require.NoError(t, err)
	indexed := indexSelectors(flattened)
	for _, selector := range []string{".roles[]", ".roles[0]", ".active", ".missing"} {
		for operator := range policy.SubjectMappingOperatorEnum_name {
			condition := &policy.Condition{SubjectExternalSelectorValue: selector, Operator: policy.SubjectMappingOperatorEnum(operator), SubjectExternalValues: []string{"admin", "true"}}
			expected, expectedError := EvaluateCondition(condition, flattened)
			actual, actualError := evaluateCondition(condition, indexed.lookup(selector))
			require.Equal(t, expected, actual)
			if expectedError != nil {
				require.EqualError(t, actualError, expectedError.Error())
			} else {
				require.NoError(t, actualError)
			}
		}
	}
}
