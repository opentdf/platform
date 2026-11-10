//nolint:forbidigo // print statements require flexibility
package cli

import (
	"encoding/json"
	"fmt"
)

var ErrPrinterExpectsCommand = fmt.Errorf("printer expects a command")

type Printer struct {
	enabled bool
	json    bool
	debug   bool
}

func newPrinter(cli *Cli) *Printer {
	p := &Printer{
		enabled: true,
		json:    false,
		debug:   false,
	}

	// if json output is enabled, disable the printer
	printJSON := cli.Flags.GetOptionalBool("json")
	p.setJSON(printJSON)

	isDebug := cli.Flags.GetOptionalBool("debug")
	p.setDebug(isDebug)

	return p
}

func (p *Printer) setJSON(json bool) {
	p.json = json
	p.enabled = !json
}

func (p *Printer) setDebug(debug bool) {
	p.debug = debug
}

const debugPrefix = "DEBUG: "

func (c *Cli) Debug(args ...interface{}) {
	if c.printer.debug {
		args = append([]interface{}{debugPrefix}, args...)
		c.Print(args...)
	}
}

func (c *Cli) Debugf(format string, args ...interface{}) {
	format = "DEBUG: " + format
	if c.printer.debug {
		c.Printf(format, args...)
	}
}

func (c *Cli) Debugln(args ...interface{}) {
	if c.printer.debug {
		args = append([]interface{}{"DEBUG: "}, args...)
		c.Println(args...)
	}
}

// PrintJSON prints the given value as json
// ignores the printer enabled flag
func (c *Cli) PrintJSON(v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		ExitWithError("failed to marshal json", err)
	}
	fmt.Println(string(b))
}

func (c *Cli) PrintIfJSON(v interface{}) {
	if c.printer.json {
		c.PrintJSON(v)
	}
}

func (c *Cli) Print(args ...interface{}) {
	if c.printer.enabled {
		fmt.Print(args...)
	}
}

func (c *Cli) Printf(format string, args ...interface{}) {
	if c.printer.enabled {
		fmt.Printf(format, args...)
	}
}

func (c *Cli) Println(args ...interface{}) {
	if c.printer.enabled {
		fmt.Println(args...)
	}
}
