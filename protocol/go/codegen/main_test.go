package main

import (
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

import (
)

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
