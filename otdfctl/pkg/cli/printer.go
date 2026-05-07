package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

var ErrPrinterExpectsCommand = errors.New("printer expects a command")

var defaultJSONOutput atomic.Bool

type Printer struct {
	enabled bool
	json    bool
	debug   bool
}

func newPrinter(json bool) *Printer {
	p := &Printer{
		enabled: true,
		json:    false,
		debug:   false,
	}

	// if json output is enabled, disable the printer
	defaultJSONOutput.Store(json)
	p.setJSON(json)

	return p
}

func (p *Printer) setJSON(json bool) {
	p.json = json
	p.enabled = !json
}

// PrintJSON prints the given value as json
// ignores the printer enabled flag
func (c *Cli) printJSON(v interface{}, w io.Writer) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		ExitWithError("failed to encode json", err)
	}
}

func (c *Cli) println(w io.Writer, args ...interface{}) {
	if c.printer.enabled {
		fmt.Fprintln(w, args...)
	}
}

func (c *Cli) SetJSONOutput(enabled bool) {
	if c.printer == nil {
		return
	}
	c.printer.setJSON(enabled)
}

func defaultPrinter() *Printer {
	json := defaultJSONOutput.Load()
	return &Printer{
		enabled: !json,
		json:    json,
	}
}
