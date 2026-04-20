package authorizationv2

import (
	"testing"

	authorizationv2proto "github.com/opentdf/platform/protocol/go/authorization/v2"
)

func TestForAttributeValues(t *testing.T) {
	fqns := []string{
		"https://example.com/attr/department/value/finance",
		"https://example.com/attr/level/value/public",
	}
	r := ForAttributeValues(fqns...)

	av, ok := r.GetResource().(*authorizationv2proto.Resource_AttributeValues_)
	if !ok {
		t.Fatal("expected AttributeValues resource")
	}
	got := av.AttributeValues.GetFqns()
	if len(got) != len(fqns) {
		t.Fatalf("fqns len = %d, want %d", len(got), len(fqns))
	}
	for i, fqn := range fqns {
		if got[i] != fqn {
			t.Errorf("fqns[%d] = %q, want %q", i, got[i], fqn)
		}
	}
}

func TestForAttributeValues_Single(t *testing.T) {
	fqn := "https://example.com/attr/department/value/finance"
	r := ForAttributeValues(fqn)

	av, ok := r.GetResource().(*authorizationv2proto.Resource_AttributeValues_)
	if !ok {
		t.Fatal("expected AttributeValues resource")
	}
	got := av.AttributeValues.GetFqns()
	if len(got) != 1 {
		t.Fatalf("fqns len = %d, want 1", len(got))
	}
	if got[0] != fqn {
		t.Errorf("fqns[0] = %q, want %q", got[0], fqn)
	}
}

func TestForRegisteredResourceValueFqn(t *testing.T) {
	fqn := "https://example.com/attr/department/value/finance"
	r := ForRegisteredResourceValueFqn(fqn)

	rr, ok := r.GetResource().(*authorizationv2proto.Resource_RegisteredResourceValueFqn)
	if !ok {
		t.Fatal("expected RegisteredResourceValueFqn resource")
	}
	if rr.RegisteredResourceValueFqn != fqn {
		t.Errorf("fqn = %q, want %q", rr.RegisteredResourceValueFqn, fqn)
	}
}

func TestForRegisteredResourceValueFqn_EmptyString(t *testing.T) {
	r := ForRegisteredResourceValueFqn("")

	rr, ok := r.GetResource().(*authorizationv2proto.Resource_RegisteredResourceValueFqn)
	if !ok {
		t.Fatal("expected RegisteredResourceValueFqn resource")
	}
	if rr.RegisteredResourceValueFqn != "" {
		t.Errorf("fqn = %q, want empty string", rr.RegisteredResourceValueFqn)
	}
}
