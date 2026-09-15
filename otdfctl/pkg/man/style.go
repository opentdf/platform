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

// plainOutput reports whether help should be rendered without colour: stdout is
// not a terminal, or NO_COLOR is set.
//
// Docs are styled during package initialization, long before any flag is
// parsed, so this reads os.Stdout directly rather than a command's configured
// output writer.
func plainOutput() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	return !term.IsTerminal(int(os.Stdout.Fd()))
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

	// Set up a new glamour instance with some options.
	//
	// NewTermRenderer has no terminal detection of its own and defaults to a
	// TrueColor profile, so `otdfctl <cmd> --help | less` emitted a wall of
	// escape sequences. Render from the ASCII style when there is no terminal to
	// colour for; the layout below is applied either way.
	ds := styles.DarkStyleConfig
	if plainOutput() {
		// The ASCII style carries no colour anywhere and already prefixes
		// headings with "# ", so it needs none of the dark-style header override
		// below. Only the shared margins apply.
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
