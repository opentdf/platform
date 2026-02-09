package containers

import (
	"os"

	tc "github.com/testcontainers/testcontainers-go"
)

func ProviderType() tc.ProviderType {
	if os.Getenv("TESTCONTAINERS_PODMAN") == "true" {
		return tc.ProviderPodman
	}

	return tc.ProviderDocker
}
