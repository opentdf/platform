package config

import (
	"context"
	"encoding/json"
	"testing"
)

func TestSecret_Literal(t *testing.T) {
	s := NewLiteralSecret("super-secret")
	if s.String() != "[REDACTED]" {
		t.Fatalf("expected redacted String, got %q", s.String())
	}
	got, err := s.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve literal: %v", err)
	}
	if got != "super-secret" {
		t.Fatalf("unexpected value: %q", got)
	}
	raw, err := s.Export()
	if err != nil || raw != "super-secret" {
		t.Fatalf("export literal: %v, %q", err, raw)
	}
}

func TestSecret_FromEnv(t *testing.T) {
	const env = "OPENTDF_TEST_SECRET"
	t.Setenv(env, "env-secret")

	s := NewEnvSecret(env)
	if s.String() != "[REDACTED]" {
		t.Fatalf("expected redacted String, got %q", s.String())
	}
	got, err := s.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve env: %v", err)
	}
	if got != "env-secret" {
		t.Fatalf("unexpected value: %q", got)
	}
}

func TestSecret_JSONRedacted(t *testing.T) {
	s := NewLiteralSecret("dont-log-me")
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "\"[REDACTED]\"" {
		t.Fatalf("expected redacted json, got %s", b)
	}
}
