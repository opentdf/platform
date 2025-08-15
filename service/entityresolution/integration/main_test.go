package integration

import (
	"log/slog"
	"os"
	"testing"
)

// TestMain sets up the test environment for top-level integration tests
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
