package man

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const styledDoc = `# Title

Some **bold** text with ` + "`inline code`" + ` and a list:

- one
- two

` + "```shell\notdfctl policy attributes list\n```" + `
`

// escape is the CSI introducer every ANSI colour sequence starts with.
const escape = "\x1b"

// TestStyleDocIsPlainWithNoColor covers the case a user can control directly.
// Test binaries run without a terminal, so the TTY branch is exercised by
// TestStyleDocIsPlainWithoutTerminal below.
func TestStyleDocIsPlainWithNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := styleDoc(styledDoc)

	require.NotEmpty(t, out)
	assert.NotContains(t, out, escape, "help text must carry no ANSI escapes when NO_COLOR is set")
	assert.Contains(t, out, "Title")
	assert.Contains(t, out, "otdfctl policy attributes list")
}

// TestStyleDocIsPlainWithoutTerminal pins the reported defect: piping --help to
// a file or a pager produced a wall of escape sequences, because the renderer
// defaulted to a TrueColor profile with no terminal detection.
func TestStyleDocIsPlainWithoutTerminal(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	require.True(t, plainOutput(), "test premise: go test output is not a terminal")

	out := styleDoc(styledDoc)

	require.NotEmpty(t, out)
	assert.NotContains(t, out, escape, "help text must carry no ANSI escapes off a terminal")
	// Content and layout survive; only colour is dropped.
	assert.Contains(t, out, "Title")
	assert.Contains(t, out, "one")
	assert.Contains(t, out, "two")
}

func TestPlainOutput(t *testing.T) {
	t.Run("NO_COLOR forces plain", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		assert.True(t, plainOutput())
	})

	t.Run("no terminal forces plain", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		assert.True(t, plainOutput())
	})
}

// TestStyleDocPreservesMarkdownStructure guards the layout tweaks applied to
// both style configs.
func TestStyleDocPreservesMarkdownStructure(t *testing.T) {
	out := styleDoc(styledDoc)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.NotEmpty(t, lines)
	assert.Contains(t, out, "# Title", "H1 keeps its '# ' prefix format")
}
