package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type inlineCfg struct {
	A Secret `mapstructure:"a"`
	B Secret `mapstructure:"b"`
	C Secret `mapstructure:"c"`
}

func TestDecodeHook_InlineForms(t *testing.T) {
	// Prepare a temp file for file: form
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(f, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv("OPENTDF_TEST_INLINE", "from-env")

	in := ServiceConfig{
		"a": "literal:abc",
		"b": "env:OPENTDF_TEST_INLINE",
		"c": "file:" + f,
	}

	var out inlineCfg
	if err := BindServiceConfig(context.Background(), in, &out); err != nil {
		t.Fatalf("bind: %v", err)
	}

	a, err := out.A.Resolve(context.Background())
	if err != nil || a != "abc" {
		t.Fatalf("literal: %v %q", err, a)
	}
	b, err := out.B.Resolve(context.Background())
	if err != nil || b != "from-env" {
		t.Fatalf("env: %v %q", err, b)
	}
	c, err := out.C.Resolve(context.Background())
	if err != nil || c != "from-file" {
		t.Fatalf("file: %v %q", err, c)
	}
}

func TestDecodeHook_MalformedDirectives(t *testing.T) {
	cases := []ServiceConfig{
		{"x": "env:"},
		{"x": "file:"},
		{"x": map[string]any{"fromEnv": ""}},
		{"x": map[string]any{"fromFile": ""}},
	}
	for _, in := range cases {
		var out struct {
			X Secret `mapstructure:"x"`
		}
		if err := BindServiceConfig(context.Background(), in, &out); err == nil {
			t.Fatalf("expected error for malformed directive: %+v", in)
		}
	}
}
