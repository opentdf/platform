package man

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessDocNoArgs(t *testing.T) {
	doc, err := ProcessDoc(`---
title: List namespaces
command:
  name: list
---

List all namespaces.
`)
	require.NoError(t, err)
	assert.Equal(t, "list", doc.Use)
}

func TestProcessDocWithArgs(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Get a resource
command:
  name: get
  arguments:
    - resource-id
---

Get a resource by ID.
`)
	require.NoError(t, err)
	assert.Equal(t, "get <resource-id>", doc.Use)
}

func TestProcessDocWithArbitraryArgs(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Do something
command:
  name: do
  arbitraryArgs:
    - optional-arg
---

Do something optionally.
`)
	require.NoError(t, err)
	assert.Equal(t, "do [optional-arg]", doc.Use)
}

func TestProcessDocWithBothArgTypes(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Authenticate with client credentials
command:
  name: client-credentials
  arguments:
    - client-id
  arbitraryArgs:
    - client-secret
---

Authenticate via client credentials flow.
`)
	require.NoError(t, err)
	assert.Equal(t, "client-credentials <client-id> [client-secret]", doc.Use)
}

func TestBuildUseString(t *testing.T) {
	tests := []struct {
		name          string
		cmdName       string
		args          []string
		arbitraryArgs []string
		want          string
	}{
		{
			name:    "name only",
			cmdName: "list",
			want:    "list",
		},
		{
			name:    "with required args",
			cmdName: "get",
			args:    []string{"id"},
			want:    "get <id>",
		},
		{
			name:          "with optional args",
			cmdName:       "run",
			arbitraryArgs: []string{"extra"},
			want:          "run [extra]",
		},
		{
			name:          "with both",
			cmdName:       "auth",
			args:          []string{"client-id"},
			arbitraryArgs: []string{"client-secret"},
			want:          "auth <client-id> [client-secret]",
		},
		{
			name:    "multiple required",
			cmdName: "copy",
			args:    []string{"src", "dst"},
			want:    "copy <src> <dst>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildUseString(tt.cmdName, tt.args, tt.arbitraryArgs)
			assert.Equal(t, tt.want, got)
		})
	}
}
