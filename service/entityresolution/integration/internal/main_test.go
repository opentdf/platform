package internal

import (
	"log/slog"
	"os"
	"testing"
)

const note = `
====================================================================================
 Entity Resolution Service (ERS) Integration Tests
 Testcontainers is used to run these integration tests. To get this working please
 ensure you have Docker/Podman installed and running.
 If using Podman, export these variables:
   export TESTCONTAINERS_PODMAN=true;
   export TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=true;
   export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock;
 If using Colima, export these variables:
   export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock";
   export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="/var/run/docker.sock";
   export TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=true;
   export TESTCONTAINERS_RYUK_DISABLED=true;
 Note: Colima does not run well on MacOS with Ryuk, so it is better to run with Ryuk disabled.
 This means you must more carefully ensure container termination.
 For more information please see: https://www.testcontainers.org/
 ---------------------------------------------------------------------------------
 Test runner hanging at '📀 starting OpenLDAP container' or '📀 starting PostgreSQL container'?
 Try restarting Docker/Podman and running the tests again.
   Docker: docker-machine restart
   Podman: podman machine stop;podman machine start
   Colima: colima restart
====================================================================================
`

func init() {
	os.Stderr.Write([]byte(note))
}

func TestMain(m *testing.M) {
	// Initialize test environment
	cleanupFunc, err := initializeTestEnvironment()
	if err != nil {
		slog.Error("Failed to initialize test environment", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Run tests
	exitCode := m.Run()

	// Cleanup
	if cleanupFunc != nil {
		cleanupFunc()
	}

	os.Exit(exitCode)
}

// initializeTestEnvironment sets up the test environment and returns a cleanup function
func initializeTestEnvironment() (func(), error) {
	// No global configuration needed - all adapter-specific setup is handled by each test scope
	return cleanup, nil
}

func cleanup() {
	// Adapter-specific cleanup is handled by each test scope
	slog.Info("Global test environment cleanup completed")
}
