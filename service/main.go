package main

import (
	"github.com/opentdf/platform/service/cmd"
	"github.com/opentdf/platform/service/tracing"
)

func main() {
	// Initialize tracer
	shutdown := tracing.InitTracer()
	defer shutdown()

	cmd.Execute()
}
