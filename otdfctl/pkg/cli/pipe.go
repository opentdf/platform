package cli

import (
	"io"
	"os"

	"github.com/opentdf/platform/otdfctl/pkg/streamio"
)

// These wrappers read their whole input into memory and call ExitWithError —
// which calls os.Exit — from inside the read, so they cannot be used anywhere
// that wants to handle the failure itself. They delegate to pkg/streamio so
// there is one implementation of "find the file argument or piped stdin" to
// maintain.
//
// New code should call pkg/streamio directly, which streams and returns
// errors instead of buffering and exiting.

// Deprecated: reads the entire input into memory and terminates the process on
// failure. Use streamio.OpenSeekable, which resolves the same "file argument or
// piped stdin" choice without buffering and returns an error.
func ReadFromArgsOrPipe(args []string, pipe *os.File) []byte {
	if len(args) > 0 {
		return ReadFromFile(args[0])
	}
	if pipe == nil {
		pipe = os.Stdin
	}
	return ReadFromPipe(pipe)
}

// Deprecated: reads the entire pipe into memory and terminates the process on
// failure. Use streamio.PipeReader, which reports whether input is present
// without consuming it, paired with io.ReadAll for the equivalent []byte.
func ReadFromPipe(in *os.File) []byte {
	r, ok, err := streamio.PipeReader(in)
	if err != nil {
		ExitWithError("failed to read stat from stdin", err)
	}
	if !ok {
		return nil
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		ExitWithError("failed to scan bytes from stdin", err)
	}
	return buf
}

// Deprecated: reads the entire file into memory with no size cap at all — not
// even the 10 GB one the tdf commands apply — and terminates the process on
// failure. Open the file and stream from it, or use utils.ReadBytesFromFile if
// a bounded in-memory read is genuinely wanted.
func ReadFromFile(filePath string) []byte {
	f, err := os.Open(filePath)
	if err != nil {
		ExitWithError("Failed to open file at path: "+filePath, err)
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		ExitWithError("Failed to read bytes from file at path: "+filePath, err)
	}
	return buf
}
