package main

import (
	"fmt"
	"os"
)

const (
	minCommandArgs    = 2
	minSubcommandArgs = 3
)

func main() {
	if len(os.Args) < minCommandArgs {
		usage()
	}

	switch os.Args[1] {
	case "provision":
		if len(os.Args) < minSubcommandArgs {
			provisionUsage()
		}
		switch os.Args[2] {
		case "keycloak":
			provisionKeycloak(os.Args[minSubcommandArgs:])
		case "fixtures":
			provisionFixtures(os.Args[minSubcommandArgs:])
		default:
			fmt.Fprintf(os.Stderr, "unknown provision target: %s\n\n", os.Args[2])
			provisionUsage()
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [args]\n\nCommands:\n  provision   Provision test infrastructure\n", os.Args[0])
	os.Exit(1)
}

func provisionUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s provision <target> [flags]\n\nTargets:\n  keycloak    Provision Keycloak realms, clients, and users\n  fixtures    Provision policy fixture data into the database\n", os.Args[0])
	os.Exit(1)
}
