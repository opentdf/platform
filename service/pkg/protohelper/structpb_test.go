package protohelper

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestStructPBCompatibleValue(t *testing.T) {
	input := map[string]interface{}{
		"attempted_strategies": []string{"claims", "ldap"},
		"nested": map[string]interface{}{
			"values": []interface{}{
				"ok",
				[]string{"a", "b"},
				map[string]interface{}{"inner": []string{"x", "y"}},
			},
		},
	}

	normalized := StructPBCompatibleValue(input)

	normalizedMap, ok := normalized.(map[string]interface{})
	if !ok {
		t.Fatalf("expected normalized result to be map[string]interface{}, got %T", normalized)
	}

	expectedStrategies := []interface{}{"claims", "ldap"}
	if !reflect.DeepEqual(normalizedMap["attempted_strategies"], expectedStrategies) {
		t.Fatalf("expected attempted_strategies %v, got %v", expectedStrategies, normalizedMap["attempted_strategies"])
	}

	if _, err := structpb.NewStruct(normalizedMap); err != nil {
		t.Fatalf("expected normalized map to be structpb-compatible, got error: %v", err)
	}
}
