package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteImports(t *testing.T) {
	m := helperMapping{
		ProtoImportPath:  "github.com/opentdf/platform/protocol/go/authorization/v2",
		ProtoImportAlias: "authorizationv2",
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "strips import line and qualifiers",
			input: `package authorizationv2

import (
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
)

func ForClientID(clientID string) *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_EntityChain{},
	}
}
`,
			want: `package authorizationv2

import (
	"github.com/opentdf/platform/protocol/go/entity"
)

func ForClientID(clientID string) *EntityIdentifier {
	return &EntityIdentifier{
		Identifier: &EntityIdentifier_EntityChain{},
	}
}
`,
		},
		{
			name: "preserves other imports",
			input: `package authorizationv2

import (
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func WithRequestToken() *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_WithRequestToken{
			WithRequestToken: wrapperspb.Bool(true),
		},
	}
}
`,
			want: `package authorizationv2

import (
	"github.com/opentdf/platform/protocol/go/entity"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func WithRequestToken() *EntityIdentifier {
	return &EntityIdentifier{
		Identifier: &EntityIdentifier_WithRequestToken{
			WithRequestToken: wrapperspb.Bool(true),
		},
	}
}
`,
		},
		{
			name:  "no-op when no matching import",
			input: "package foo\n\nfunc Bar() {}\n",
			want:  "package foo\n\nfunc Bar() {}\n",
		},
		{
			name: "does not strip partial alias matches",
			input: `package authorizationv2

import (
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
)

// authorizationv2helper is not a qualifier reference
var authorizationv2helper = "should stay"
func F() *authorizationv2.EntityIdentifier { return nil }
`,
			want: `package authorizationv2

// authorizationv2helper is not a qualifier reference
var authorizationv2helper = "should stay"
func F() *EntityIdentifier { return nil }
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rewriteImports(tt.input, m)
			if got != tt.want {
				t.Errorf("rewriteImports() mismatch\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
		})
	}
}

func TestRemoveGenFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a mix of files: .gen.go (should be removed), .pb.go and .go (should survive)
	files := map[string]bool{
		"entity_identifier.gen.go": false, // expect removed
		"other_helper.gen.go":      false, // expect removed
		"authorization.pb.go":      true,  // expect kept
		"authorization_grpc.pb.go": true,  // expect kept
		"regular.go":               true,  // expect kept
	}
	for name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := removeGenFiles(dir); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	remaining := make(map[string]bool)
	for _, e := range entries {
		remaining[e.Name()] = true
	}

	for name, shouldExist := range files {
		if shouldExist && !remaining[name] {
			t.Errorf("%s was removed but should have been kept", name)
		}
		if !shouldExist && remaining[name] {
			t.Errorf("%s was kept but should have been removed", name)
		}
	}
}

func TestCopyHelpers(t *testing.T) {
	m := helperMapping{
		Source:           "test-pkg",
		Target:           "test-pkg",
		ProtoImportPath:  "github.com/example/proto/test",
		ProtoImportAlias: "testpkg",
	}

	srcDir := filepath.Join(t.TempDir(), "src")
	dstDir := filepath.Join(t.TempDir(), "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Source .go file that should be copied and transformed.
	helperContent := `package testpkg

import (
	testpkg "github.com/example/proto/test"
)

func NewFoo() *testpkg.Foo {
	return &testpkg.Foo{}
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "helper.go"), []byte(helperContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// _test.go file that should be skipped.
	if err := os.WriteFile(filepath.Join(srcDir, "helper_test.go"), []byte("package testpkg\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Non-Go file that should be skipped.
	if err := os.WriteFile(filepath.Join(srcDir, "README.md"), []byte("# readme\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-existing stale .gen.go that should be cleaned up.
	staleFile := filepath.Join(dstDir, "old_helper.gen.go")
	if err := os.WriteFile(staleFile, []byte("package testpkg\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyHelpers(srcDir, dstDir, m); err != nil {
		t.Fatalf("copyHelpers failed: %v", err)
	}

	// Verify the transformed file was written with .gen.go suffix.
	genFile := filepath.Join(dstDir, "helper.gen.go")
	content, err := os.ReadFile(genFile)
	if err != nil {
		t.Fatalf("expected helper.gen.go to exist: %v", err)
	}

	got := string(content)

	// Verify generated header is prepended.
	if !strings.HasPrefix(got, generatedHeader) {
		t.Errorf("missing generated header, starts with: %q", got[:min(len(got), 60)])
	}

	// Verify import rewriting happened (self-referencing import removed, qualifier stripped).
	if strings.Contains(got, `"github.com/example/proto/test"`) {
		t.Error("self-referencing import was not stripped")
	}
	if strings.Contains(got, "testpkg.Foo") {
		t.Error("qualifier was not stripped from type references")
	}
	if !strings.Contains(got, "*Foo") {
		t.Error("expected unqualified type reference *Foo")
	}

	// Verify _test.go was not copied.
	if _, err := os.Stat(filepath.Join(dstDir, "helper_test.gen.go")); err == nil {
		t.Error("_test.go file should not be copied")
	}

	// Verify non-Go file was not copied.
	if _, err := os.Stat(filepath.Join(dstDir, "README.gen.go")); err == nil {
		t.Error("non-Go file should not be copied")
	}

	// Verify stale .gen.go was removed.
	if _, err := os.Stat(staleFile); err == nil {
		t.Error("stale old_helper.gen.go should have been removed")
	}
}
