package cli

import (
	"io"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ExitCodeSuccess = 0
	ExitCodeError   = 1
)

func ExitWithError(errMsg string, err error) {
	// This is temporary until we can refactor the code to use the Cli struct
	(&Cli{printer: &Printer{enabled: true}}).ExitWithError(errMsg, err)
}

func ExitWithNotFoundError(errMsg string, err error) {
	// This is temporary until we can refactor the code to use the Cli struct
	(&Cli{printer: &Printer{enabled: true}}).ExitWithNotFoundError(errMsg, err)
}

func ExitWithWarning(warnMsg string) {
	// This is temporary until we can refactor the code to use the Cli struct
	(&Cli{printer: &Printer{enabled: true}}).ExitWithWarning(warnMsg)
}

// ExitWithError prints an error message and exits with a non-zero status code.
func (c *Cli) ExitWithError(errMsg string, err error) {
	c.ExitWithNotFoundError(errMsg, err)
	c.ExitWith(ErrorMessage(errMsg, err), ErrorJSON(errMsg, err), ExitCodeError, os.Stderr)
}

// ExitWithNotFoundError prints an error message and exits with a non-zero status code if the error is a NotFound error.
func (c *Cli) ExitWithNotFoundError(errMsg string, err error) {
	if err != nil {
		if e, ok := status.FromError(err); ok && e.Code() == codes.NotFound {
			c.ExitWith(
				ErrorMessage(errMsg+": not found", nil),
				MessageJSON("ERROR", errMsg+": not found"),
				ExitCodeError,
				os.Stderr,
			)
		}
	}
}

func (c *Cli) ExitWithWarning(warnMsg string) {
	c.ExitWith(WarningMessage(warnMsg), WarningJSON(warnMsg), ExitCodeError, os.Stderr)
}

func (c *Cli) ExitWithSuccess(msg string) {
	c.ExitWith(SuccessMessage(msg), SuccessJSON(msg), ExitCodeSuccess, os.Stdout)
}

func (c *Cli) ExitWithMessage(msg string, code int) {
	if c.printer.enabled {
		c.println(os.Stdout, msg)
		os.Exit(code)
	}
}

func (c *Cli) ExitWithJSON(v interface{}, code int) {
	if c.printer.json {
		c.printJSON(v, os.Stdout)
		os.Exit(code)
	}
}

// exitWith is the core exit function that handles both JSON and styled output
// It writes to the appropriate stream (stdout for success, stderr for errors/warnings)
func (c *Cli) ExitWith(styledMsg string, jsonMsg interface{}, code int, w io.Writer) {
	if c.printer.json {
		c.printJSON(jsonMsg, w)
	} else {
		c.println(w, styledMsg)
	}
	os.Exit(code)
}
