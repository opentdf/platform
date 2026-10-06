// Command benchmark runs the integration benchmarks reported by CI.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		exitWithError(errors.New("usage: benchmark <bulk|tdf|traces> [flags]"))
	}

	var err error
	switch os.Args[1] {
	case "bulk":
		err = runBulk(os.Args[2:])
	case "tdf":
		err = runTDF(os.Args[2:])
	case "traces":
		err = runTraces(os.Args[2:])
	default:
		err = fmt.Errorf("unknown benchmark %q", os.Args[1])
	}
	if err != nil {
		exitWithError(err)
	}
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, "benchmark failed:", err)
	os.Exit(1)
}
