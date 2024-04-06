package main

import "github.com/arkavo-org/opentdf-platform/service/pkg/server"

func main() {
	err := server.Start(
		server.WithWaitForShutdownSignal(),
		server.WithConfigFile("opentdf.yaml"),
		server.WithConfigKey("opentdf"),
	)
	if err != nil {
		panic(err)
	}
}
