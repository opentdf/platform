package main

import (
	"log"

	"github.com/arkavo-org/opentdf-platform/service/pkg/server"
)

var Version string

func main() {
	log.Printf("Version: %s", Version)
	err := server.Start(
		server.WithWaitForShutdownSignal(),
		server.WithConfigFile("opentdf.yaml"),
		server.WithConfigKey("opentdf"),
	)
	if err != nil {
		panic(err)
	}
}
