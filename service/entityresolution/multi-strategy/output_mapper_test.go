package multistrategy

import (
	"reflect"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

func TestOutputMapper_MapResult_PostgresObject(t *testing.T) {
	om := NewOutputMapper()
	raw := &types.RawResult{
		Data: map[string]interface{}{
			"attributes": `{"department":"Engineering","clearance":"secret"}`,
		},
		Metadata: map[string]interface{}{
			"provider_type": "sql",
		},
	}
	mappings := []types.OutputMapping{
		{SourceColumn: "attributes", ClaimName: "user_attributes", Transformation: "postgres_object"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]any{
		"department": "Engineering",
		"clearance":  "secret",
	}
	got, ok := result.Claims["user_attributes"].(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any claim, got %T", result.Claims["user_attributes"])
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("claims mismatch: got %#v, want %#v", got, want)
	}
}

func TestOutputMapper_MapResult_PostgresArray(t *testing.T) {
	om := NewOutputMapper()
	raw := &types.RawResult{
		Data: map[string]interface{}{
			"groups": "{admin,user,finance}",
		},
		Metadata: map[string]interface{}{
			"provider_type": "sql",
		},
	}
	mappings := []types.OutputMapping{
		{SourceColumn: "groups", ClaimName: "group_memberships", Transformation: "postgres_array"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"admin", "user", "finance"}
	got, ok := result.Claims["group_memberships"].([]string)
	if !ok {
		t.Fatalf("expected []string claim, got %T", result.Claims["group_memberships"])
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("claims mismatch: got %#v, want %#v", got, want)
	}
}

func TestOutputMapper_MapResult_CommonTransformations(t *testing.T) {
	om := NewOutputMapper()
	raw := &types.RawResult{
		Data: map[string]interface{}{
			"email":    "  User@Example.COM  ",
			"roles":    "admin,,analyst , reviewer",
			"nickname": "  bob  ",
		},
		Metadata: map[string]interface{}{
			"provider_type": "sql",
		},
	}
	mappings := []types.OutputMapping{
		{SourceColumn: "email", ClaimName: "email_lower", Transformation: "lowercase"},
		{SourceColumn: "roles", ClaimName: "roles", Transformation: "csv_to_array"},
		{SourceColumn: "nickname", ClaimName: "nickname", Transformation: "trim"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Claims["email_lower"]; got != "  user@example.com  " {
		t.Errorf("email_lower: got %v", got)
	}
	if got, ok := result.Claims["roles"].([]string); !ok || !reflect.DeepEqual(got, []string{"admin", "analyst", "reviewer"}) {
		t.Errorf("roles: got %#v", result.Claims["roles"])
	}
	if got := result.Claims["nickname"]; got != "bob" {
		t.Errorf("nickname: got %v", got)
	}
}

func TestOutputMapper_MapResult_UnknownTransformationErrors(t *testing.T) {
	om := NewOutputMapper()
	raw := &types.RawResult{
		Data:     map[string]interface{}{"x": "y"},
		Metadata: map[string]interface{}{"provider_type": "sql"},
	}
	mappings := []types.OutputMapping{
		{SourceColumn: "x", ClaimName: "x", Transformation: "does_not_exist"},
	}

	if _, err := om.MapResult(raw, mappings, "entity-1"); err == nil {
		t.Fatal("expected error for unknown transformation, got nil")
	}
}

func TestOutputMapper_MapResult_MissingSourceIsSkipped(t *testing.T) {
	om := NewOutputMapper()
	raw := &types.RawResult{
		Data:     map[string]interface{}{"present": "yes"},
		Metadata: map[string]interface{}{"provider_type": "sql"},
	}
	mappings := []types.OutputMapping{
		{SourceColumn: "present", ClaimName: "present"},
		{SourceColumn: "absent", ClaimName: "absent"},
	}

	result, err := om.MapResult(raw, mappings, "entity-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := result.Claims["absent"]; exists {
		t.Error("absent claim should not be set")
	}
	if result.Claims["present"] != "yes" {
		t.Errorf("present: got %v", result.Claims["present"])
	}
}
