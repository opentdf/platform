package cli

type cliOptions struct {
	printerJSON bool
}

type cliVariadicOption func(cliOptions) cliOptions

// WithPrintJSON is a variadic option that enforces JSON output for the printer
func WithPrintJSON() cliVariadicOption {
	return func(o cliOptions) cliOptions {
		o.printerJSON = true
		return o
	}
}
