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

// stdoutIsTerminal is replaceable in tests.
var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// plainOutput reports whether help should render without colour.
func plainOutput() bool {
	return os.Getenv("NO_COLOR") != "" || !stdoutIsTerminal()
}

func styleDoc(doc string) string {
	// Size wrapping for the stream that receives help output.
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w = termWidthDefault
	}
	if w > termWidthWide {
		w = termWidthWide
	}

	// NewTermRenderer requires an explicit plain style for redirected output.
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
