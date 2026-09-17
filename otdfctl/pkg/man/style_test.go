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

// onTerminal pretends stdout is a terminal, which a test binary's never is.
func onTerminal(t *testing.T) {
	t.Helper()
	prev := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = prev })
}

func TestPlainOutput(t *testing.T) {
	t.Run("no terminal forces plain", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		assert.True(t, plainOutput())
	})

	// Without the fake terminal this subtest passes whether or not plainOutput
	// reads NO_COLOR at all, because there is no terminal either way.
	t.Run("NO_COLOR forces plain on a terminal", func(t *testing.T) {
		onTerminal(t)
		require.False(t, plainOutput(), "test premise: a terminal alone is not plain")

		t.Setenv("NO_COLOR", "1")
		assert.True(t, plainOutput())
	})
}

// The dark style needs an explicit H1 override to match the ASCII style's "# "
// prefix. Asserting it off a terminal proves nothing: the ASCII style supplies
// that prefix on its own, so the override could be deleted and the test pass.
func TestStyleDocPreservesMarkdownStructure(t *testing.T) {
	t.Run("without a terminal", func(t *testing.T) {
		assert.Contains(t, styleDoc(styledDoc), "# Title", "H1 keeps its '# ' prefix")
	})

	// The dark style colours the heading but does not prefix it, so the two
	// branches do not render an H1 the same way. Asserting the prefix here would
	// fail, and asserting it only off a terminal, as this test used to, said
	// nothing about the styled branch. Compare the branches instead: collapsing
	// one into the other is the failure that matters.
	t.Run("on a terminal", func(t *testing.T) {
		plain := styleDoc(styledDoc)

		onTerminal(t)
		t.Setenv("NO_COLOR", "")
		styled := styleDoc(styledDoc)

		assert.NotEqual(t, plain, styled, "the styled branch must not render as the plain one")
		assert.Contains(t, styled, "Title", "content survives either way")
		assert.Contains(t, styled, "otdfctl policy attributes list")

		// Counted, not merely present: the heading override colours the H1 under
		// either style config, so a handful of escapes proves nothing about the
		// body. The dark style emits four figures for this document.
		assert.Zero(t, strings.Count(plain, escape))
		assert.Greater(t, strings.Count(styled, escape), 100, "the whole document is styled, not just the heading")
	})
}
