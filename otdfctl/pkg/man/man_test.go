package man

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/adrg/frontmatter"
	docsEmbed "github.com/opentdf/platform/otdfctl/docs"
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
	// A doc that declares no arguments rejects them. Leaving Args nil made cobra
	// accept and silently ignore anything passed.
	require.NotNil(t, doc.Args)
	require.NoError(t, doc.Args(&doc.Command, []string{}))
	require.Error(t, doc.Args(&doc.Command, []string{"unexpected"}))
}

// TestProcessDocArgsInNameAreNotRejected covers the docs that declare their
// positional inline, as with `name: encrypt [file]`, rather than through the
// arguments metadata. Those commands read args[0], so they must not be given
// cobra.NoArgs.
func TestProcessDocArgsInNameAreNotRejected(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Encrypt a file
command:
  name: encrypt [file]
---

Encrypt a file.
`)
	require.NoError(t, err)
	assert.Equal(t, "encrypt [file]", doc.Use)
	if doc.Args != nil {
		require.NoError(t, doc.Args(&doc.Command, []string{"some-file"}))
	}
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

func TestProcessDocWithBothArgTypesValidator(t *testing.T) {
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
	require.NoError(t, doc.Args(&doc.Command, []string{"id"}))
	require.NoError(t, doc.Args(&doc.Command, []string{"id", "secret"}))
	require.Error(t, doc.Args(&doc.Command, []string{}))
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

// knownCommandKeys are the keys ProcessDoc reads out of a doc's `command`
// mapping. "description" is listed because four docs set it and nothing reads
// it; it is inert rather than dangerous, unlike a misspelled operand key.
var knownCommandKeys = map[string]bool{
	"name":          true,
	"arguments":     true,
	"arbitraryArgs": true,
	"hidden":        true,
	"aliases":       true,
	"flags":         true,
	"description":   true,
}

// ProcessDoc gives a doc that declares no operands cobra.NoArgs, so a doc that
// declares them under a key ProcessDoc does not read has its operands rejected
// at runtime with nothing reported at parse time. auth/client-credentials.md
// wrote `args:` and `arbitrary_args:` against `arguments:` and `arbitraryArgs:`,
// which left its two operands invisible while its handler went on indexing them.
func TestEveryDocDeclaresOperandsWhereProcessDocReadsThem(t *testing.T) {
	checked := 0
	err := fs.WalkDir(docsEmbed.ManFiles, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		b, readErr := docsEmbed.ManFiles.ReadFile(path)
		require.NoError(t, readErr, path)

		var raw struct {
			Command map[string]any `yaml:"command"`
		}
		if _, perr := frontmatter.Parse(strings.NewReader(string(b)), &raw); perr != nil {
			//nolint:nilerr // skipping the doc is the point: ProcessDoc's own tests cover malformed frontmatter
			return nil
		}
		for key := range raw.Command {
			assert.True(t, knownCommandKeys[key],
				"%s: `command.%s` is not read by ProcessDoc, so its value is silently dropped", path, key)
		}
		checked++
		return nil
	})
	require.NoError(t, err)
	assert.Positive(t, checked, "no docs were checked")
}

// The four commands whose handlers index args, read from the shipped docs
// rather than from synthetic ones, since the defect above was a mismatch
// between what the tests declared and what the docs actually said.
func TestShippedDocsKeepTheirOperands(t *testing.T) {
	for _, key := range []string{"encrypt", "decrypt", "inspect", "auth/client-credentials"} {
		t.Run(key, func(t *testing.T) {
			doc := Docs.En[key]
			require.NotNil(t, doc, "doc not found in the registry")
			require.NotNil(t, doc.Args)
			assert.NoError(t, doc.Args(&doc.Command, []string{"operand"}),
				"the handler indexes args, so the operand has to reach it")
		})
	}
}
