package cli

import (
	"os"
	"strconv"
	"strings"

	"github.com/opentdf/platform/otdfctl/pkg/config"
	"golang.org/x/term"
)

func CommaSeparated(values []string) string {
	return "[" + strings.Join(values, ", ") + "]"
}

var defaultWidth = 80

// Returns the terminal width (overridden by env var for testing)
func TermWidth() int {
	var (
		w   int
		err error
	)
	testSize := os.Getenv(config.TestTerminalWidth)
	if testSize == "" {
		w, _, err = term.GetSize(0)
		if err != nil {
			return defaultWidth
		}
		return w
	}
	if w, err = strconv.Atoi(testSize); err != nil {
		return defaultWidth
	}
	return w
}

func PrettyList(values []string) string {
	var b strings.Builder
	for i, v := range values {
		if i == len(values)-1 {
			b.WriteString("or ")
			b.WriteString(v)
		} else {
			b.WriteString(v)
			b.WriteString(", ")
		}
	}
	return b.String()
}
