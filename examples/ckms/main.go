package main

import (
	"fmt"
	"log"

	"github.com/opentdf/platform/examples/ckms/vault"
	"github.com/opentdf/platform/service/pkg/server"
)

func start() {
	configFile := "./examples/ckms/cfg-vault.yaml"
	configKey := "exckms"

	customStartOptions := []server.StartOptions{
		server.WithWaitForShutdownSignal(),
		server.WithConfigFile(configFile),
		server.WithConfigKey(configKey),
	}

	// Start the platform server with the custom options
	if err := server.Start(customStartOptions...); err != nil {
		log.Fatalf("Failed to start the server: %v", err)
	}
}

func main() {
	if true {
		fmt.Println("Lookups...")
		fmt.Println(vault.GetSecretWithAppRole())
		return
	}
	fmt.Println("Starting CKMS...")
	start()
	fmt.Println("CKMS started successfully.")
}
