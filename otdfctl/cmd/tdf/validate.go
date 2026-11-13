package tdf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

// ExitCodeInvalidTDF is the exit status of `validate` when the check ran to
// completion and the file is not a valid TDF. It is deliberately not 1, which
// otdfctl uses for usage errors and unreadable input, so a caller can tell
// "not a TDF" apart from "could not check".
const ExitCodeInvalidTDF = 3

// validateResult is the single JSON line `validate` writes to stdout.
type validateResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

var (
	validateDoc = man.Docs.GetCommand("validate", man.WithRun(validateRun))
	ValidateCmd = &validateDoc.Command
)

// validateRun deliberately never builds a handler: validation is offline, so it
// must not need a profile, credentials, or a reachable platform.
func validateRun(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args, cli.WithPrintJSON())

	result, err := validateFile(args[0])
	if err != nil {
		c.ExitWithError("could not validate TDF", err)
	}

	code := cli.ExitCodeSuccess
	if !result.Valid {
		code = ExitCodeInvalidTDF
	}
	if err := writeValidateResult(os.Stdout, result); err != nil {
		c.ExitWithError("failed to write result", err)
	}
	os.Exit(code)
}

// writeValidateResult writes result as one line of compact JSON. cli's JSON
// printer indents, which would break the one-line contract.
func writeValidateResult(w io.Writer, result validateResult) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(result)
}

// validateFile runs sdk.IsValidTdf on the file at path. It returns an error
// only when the check could not be carried out; an invalid TDF is a result.
func validateFile(path string) (validateResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return validateResult{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return validateResult{}, err
	}
	// IsValidTdf seeks from the end of the input. On a FIFO or device that seek
	// fails, and seek errors are not told apart from a corrupt archive (see
	// readErrRecorder), so the failure would be misreported as an invalid TDF.
	if !info.Mode().IsRegular() {
		return validateResult{}, fmt.Errorf("%s: not a regular file", path)
	}

	return validateReader(f)
}

// validateReader runs sdk.IsValidTdf on r, separating read failures, which mean
// the check could not run, from the TDF being malformed.
func validateReader(r io.ReadSeeker) (validateResult, error) {
	in := &readErrRecorder{ReadSeeker: r}
	valid, err := sdk.IsValidTdf(in)
	if in.err != nil {
		return validateResult{}, in.err
	}
	if valid {
		return validateResult{Valid: true}, nil
	}
	reason := "not a valid TDF"
	if err != nil {
		reason = err.Error()
	}
	return validateResult{Valid: false, Reason: reason}, nil
}

// readErrRecorder remembers the first read error other than io.EOF.
// IsValidTdf folds every failure into its own error, so without this an I/O
// fault partway through the file would be indistinguishable from a malformed
// TDF. Seek errors are not recorded: on a regular file the only one is a
// negative offset, which comes from a truncated or corrupt archive.
type readErrRecorder struct {
	io.ReadSeeker
	err error
}

func (r *readErrRecorder) Read(p []byte) (int, error) {
	n, err := r.ReadSeeker.Read(p)
	if err != nil && r.err == nil && !errors.Is(err, io.EOF) {
		r.err = err
	}
	return n, err
}

func InitValidateCommand() {
	validateDoc.GroupID = TDF
}
