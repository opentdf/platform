package authorizationv2

import (
	"testing"
)

func TestForAction(t *testing.T) {
	name := "decrypt"
	a := ForAction(name)

	if a.GetName() != name {
		t.Errorf("name = %q, want %q", a.GetName(), name)
	}
}

func TestForAction_EmptyString(t *testing.T) {
	a := ForAction("")

	if a.GetName() != "" {
		t.Errorf("name = %q, want empty string", a.GetName())
	}
}
