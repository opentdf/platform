package sdk

import (
	"strings"
	"testing"
)

func TestWithPolicyFrom_NilReader(t *testing.T) {
	cfg := &TDFConfig{}
	err := WithPolicyFrom(nil)(cfg)
	if err == nil {
		t.Fatal("expected error for nil Reader")
	}
	if !strings.Contains(err.Error(), "nil Reader") {
		t.Errorf("error = %v, want to mention nil Reader", err)
	}
}
