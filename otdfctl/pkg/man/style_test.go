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

func TestStyleDocIsPlainWithNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	setTerminal(t, true)

	out := styleDoc(styledDoc)

	require.NotEmpty(t, out)
	assert.NotContains(t, out, escape, "help text must carry no ANSI escapes when NO_COLOR is set")
	assert.Contains(t, out, "Title")
	assert.Contains(t, out, "otdfctl policy attributes list")
}

func TestStyleDocIsPlainWithoutTerminal(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	setTerminal(t, false)

	out := styleDoc(styledDoc)

	require.NotEmpty(t, out)
	assert.NotContains(t, out, escape, "help text must carry no ANSI escapes off a terminal")
	assert.Contains(t, out, "Title")
	assert.Contains(t, out, "one")
	assert.Contains(t, out, "two")
}

func setTerminal(t *testing.T, terminal bool) {
	t.Helper()
	prev := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return terminal }
	t.Cleanup(func() { stdoutIsTerminal = prev })
}

func TestPlainOutput(t *testing.T) {
	t.Run("no terminal forces plain", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		setTerminal(t, false)
		assert.True(t, plainOutput())
	})

	t.Run("NO_COLOR forces plain on a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		setTerminal(t, true)
		require.False(t, plainOutput())

		t.Setenv("NO_COLOR", "1")
		assert.True(t, plainOutput())
	})
}

func TestStyleDocPreservesMarkdownStructure(t *testing.T) {
	t.Run("without a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		setTerminal(t, false)
		assert.Contains(t, styleDoc(styledDoc), "# Title", "H1 keeps its '# ' prefix")
	})

	t.Run("on a terminal", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		setTerminal(t, false)
		plain := styleDoc(styledDoc)

		setTerminal(t, true)
		styled := styleDoc(styledDoc)

		assert.NotEqual(t, plain, styled, "the styled branch must not render as the plain one")
		assert.Contains(t, styled, "Title", "content survives either way")
		assert.Contains(t, styled, "otdfctl policy attributes list")

		assert.Zero(t, strings.Count(plain, escape))
		assert.Greater(t, strings.Count(styled, escape), 100, "the whole document is styled, not just the heading")
	})
}
