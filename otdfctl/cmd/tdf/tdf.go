package tdf

import (
	"io"
	"os"

	"github.com/opentdf/otdfctl/pkg/cli"
)

const (
	Size1MB     = 1024 * 1024
	MaxFileSize = int64(10 * 1024 * 1024 * 1024) // 10 GB
	TDF         = "TDF"
	// GroupID is the group ID for TDF commands
	GroupID = TDF
)

func readPipedStdin() []byte {
	stat, err := os.Stdin.Stat()
	if err != nil {
		cli.ExitWithError("Failed to read stat from stdin", err)
	}
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		buf, err := io.ReadAll(os.Stdin)
		if err != nil {
			cli.ExitWithError("failed to scan bytes from stdin", err)
		}
		return buf
	}
	return nil
}
