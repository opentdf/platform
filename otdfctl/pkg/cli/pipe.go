package cli

import (
	"io"
	"os"
)

// The helpers in this file read their whole input into memory and call
// ExitWithError — which calls os.Exit — from inside the read. Both make them
// unsuitable for payloads of unbounded size and unusable from anywhere that
// wants to handle the failure itself. They are kept because this package is
// exported and may have callers outside this repository.
//
// New code should use pkg/streamio, which streams and returns errors.

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
// without consuming it.
func ReadFromPipe(in *os.File) []byte {
	stat, err := in.Stat()
	if err != nil {
		ExitWithError("failed to read stat from stdin", err)
	}
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		buf, err := io.ReadAll(in)
		if err != nil {
			ExitWithError("failed to scan bytes from stdin", err)
		}
		return buf
	}
	return nil
}

// Deprecated: reads the entire file into memory with no size cap at all — not
// even the 10 GB one the tdf commands apply — and terminates the process on
// failure. Open the file and stream from it, or use utils.ReadBytesFromFile if
// a bounded in-memory read is genuinely wanted.
func ReadFromFile(filePath string) []byte {
	fileToEncrypt, err := os.Open(filePath)
	if err != nil {
		ExitWithError("Failed to git open file at path: "+filePath, err)
	}
	defer fileToEncrypt.Close()

	bytes, err := io.ReadAll(fileToEncrypt)
	if err != nil {
		ExitWithError("Failed to read bytes from file at path: "+filePath, err)
	}
	return bytes
}
