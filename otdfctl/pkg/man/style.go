//nolint:mnd // styling is magic
package man

import (
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	"github.com/charmbracelet/glamour/styles"
	"golang.org/x/term"
)

var (
	termWidthDefault = 80
	termWidthWide    = 120
)

func styleDoc(doc string) string {
	w, _, err := term.GetSize(0)
	if err != nil {
		w = termWidthDefault
	}
	if w > termWidthWide {
		w = termWidthWide
	}
	// Set up a new glamour instance
	// with some options
	ds := styles.DarkStyleConfig
	// ls := glamour.DefaultStyles["light"]

	ds.Document.Margin = uintPtr(0)
	ds.Paragraph.Margin = uintPtr(2)
	// Capitalize headers
	ds.H1.StylePrimitive = ansi.StylePrimitive{
		Color:  stringPtr("#F1F1F1"),
		Format: "# {{.text}}",
	}
	r, _ := glamour.NewTermRenderer(
		// glamour.WithAutoStyle(),
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
