package protohelper

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestStructPBCompatibleValue(t *testing.T) {
	input := map[string]interface{}{
		"attempted_strategies": []string{"claims", "ldap"},
		"scores":               []float64{1.5, 2.5},
		"flags":                []bool{true, false},
		"identifiers":          []int{1, 2},
		"nested": map[string]interface{}{
			"values": []interface{}{
				"ok",
				[]string{"a", "b"},
				map[string]interface{}{
					"inner": []bool{true, false},
				},
			},
		},
	}

	normalized := StructPBCompatibleValue(input)
	normalizedMap, ok := normalized.(map[string]interface{})
	require.True(t, ok, "normalized result has type %T", normalized)

	require.Equal(t, []interface{}{"claims", "ldap"}, normalizedMap["attempted_strategies"])
	require.Equal(t, []interface{}{1.5, 2.5}, normalizedMap["scores"])
	require.Equal(t, []interface{}{true, false}, normalizedMap["flags"])
	require.Equal(t, []interface{}{1, 2}, normalizedMap["identifiers"])

	_, err := structpb.NewStruct(normalizedMap)
	require.NoError(t, err)
}
