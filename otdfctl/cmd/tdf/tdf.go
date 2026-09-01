package tdf

import (
	"io"
	"os"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/streamio"
)

const (
	Size1MB     = 1024 * 1024
	MaxFileSize = int64(10 * 1024 * 1024 * 1024) // 10 GB
	TDF         = "TDF"
	// GroupID is the group ID for TDF commands
	GroupID = TDF
)

// readPipedStdin returns the whole of piped stdin, or nil when stdin is a
// terminal or an empty redirect.
//
// Detection is delegated to streamio.PipeReader so there is a single answer to
// "is there piped input?" across the CLI. The read itself is still unbounded;
// callers that must not hold the payload in memory should use
// streamio.OpenSeekable instead.
func readPipedStdin() []byte {
	r, ok, err := streamio.PipeReader(os.Stdin)
	if err != nil {
		cli.ExitWithError("failed to scan bytes from stdin", err)
	}
	if !ok {
		return nil
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		cli.ExitWithError("failed to scan bytes from stdin", err)
	}
	return buf
}
