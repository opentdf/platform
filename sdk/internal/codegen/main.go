package main

import (
	"log"

	"github.com/opentdf/platform/sdk/internal/codegen/runner"
)

func main() {
	if err := runner.Generate(); err != nil {
		log.Fatal(err)
	}
}
