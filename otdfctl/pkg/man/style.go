//nolint:mnd // styling is magic
package man

import (
	"os"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	"github.com/charmbracelet/glamour/styles"
	"golang.org/x/term"
)

var (
	termWidthDefault = 80
	termWidthWide    = 120
)

// stdoutIsTerminal is a variable so the styled branch is reachable from a test;
// a test binary's stdout is never a terminal.
var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// plainOutput reports whether help should render without colour. Docs are
// styled during package initialization, long before a flag is parsed, so this
// reads os.Stdout rather than a command's configured writer.
func plainOutput() bool {
	return os.Getenv("NO_COLOR") != "" || !stdoutIsTerminal()
}

func styleDoc(doc string) string {
	// Measure stdout, the stream the help is written to. Reading fd 0 sized the
	// wrap against stdin, which is the wrong stream whenever either one is
	// redirected.
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w = termWidthDefault
	}
	if w > termWidthWide {
		w = termWidthWide
	}

	// NewTermRenderer has no terminal detection and defaults to TrueColor, so
	// piping --help emitted raw escapes. The ASCII style carries no colour and
	// already prefixes headings, so it needs no override; the margins below
	// apply either way.
	ds := styles.DarkStyleConfig
	if plainOutput() {
		ds = styles.NoTTYStyleConfig
	} else {
		// Capitalize headers
		ds.H1.StylePrimitive = ansi.StylePrimitive{
			Color:  stringPtr("#F1F1F1"),
			Format: "# {{.text}}",
		}
	}

	ds.Document.Margin = uintPtr(0)
	ds.Paragraph.Margin = uintPtr(2)
	r, _ := glamour.NewTermRenderer(
		glamour.WithStyles(ds),
		glamour.WithWordWrap(w),
		glamour.WithPreservedNewLines(),
	)

	// Render the content
	out, _ := r.Render(doc)

	return out
}

func stringPtr(s string) *string { return &s }
func uintPtr(u uint) *uint       { return &u }
