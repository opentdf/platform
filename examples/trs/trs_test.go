package trs

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/opentdf/platform/service/pkg/server"
	"github.com/stretchr/testify/assert"
)

const (
	startupDelay = 6 * time.Second // Give server time to start
)

var (
	workspaceFolderAbsPath string
	originalDir            string
)

func TestMain(m *testing.M) {
	// Setup: Get the current file's directory
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintf(os.Stderr, "Failed to get current file path\n")
		os.Exit(1)
	}

	// Save current working directory to restore it at the end
	var err error
	originalDir, err = os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current directory: %v\n", err)
		os.Exit(1)
	}

	// Users of the TRS recipe will need to modify the following statement to point to the root of the project
	// Set the relative path to the workspace (root) folder
	workspaceRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	workspaceFolderAbsPath, err = filepath.Abs(workspaceRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get absolute path: %v\n", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup: Restore original working directory
	if originalDir != "" {
		if err := os.Chdir(originalDir); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to restore original directory: %v\n", err)
		}
	}

	os.Exit(code)
}

func makeConfigFile(workingDirectory string) (string, error) {
	// Using the workingDirectory, perform 'cp opentdf-dev.yaml opentdf.yaml'
	// then, return the full path to the config file

	// Copy
	configFile := filepath.Join(workingDirectory, "opentdf-dev.yaml")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return "", fmt.Errorf("config file %s does not exist", configFile)
	}
	// Create a new config file
	newConfigFile := filepath.Join(workingDirectory, "opentdf.yaml")

	// Copy the file
	input, err := os.ReadFile(configFile)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	if err := os.WriteFile(newConfigFile, input, 0o644); err != nil {
		return "", fmt.Errorf("failed to write config file: %w", err)
	}
	return newConfigFile, nil
}

// It takes a done channel to signal when it should stop.
// It also takes a WaitGroup to signal when it has finished.
func backgroundPlatformServer(t *testing.T, id int, wg *sync.WaitGroup, configFile string, done <-chan struct{}) {
	defer wg.Done() // Signal that this goroutine has finished when it returns

	cwd, _ := os.Getwd()
	t.Logf("Worker %d: Arranging goroutine in working directory: %s\n", id, cwd)

	serverExited := make(chan error, 1) // Channel to capture error from server.Start

	// Run server.Start in a goroutine so backgroundPlatformServer can react to 'done'
	go func() {
		serverCwd, _ := os.Getwd()
		t.Logf("Worker %d: Preparing to start server in working directory: %s\n", id, serverCwd)

		err := server.Start(
			server.WithWaitForShutdownSignal(), // Shutdown when SIGINT or SIGTERM is received
			server.WithConfigFile(configFile),
			server.WithServices(NewRegistration()),
			server.WithPublicRoutes([]string{
				"/trs/**",
			}),
		)
		// Send the result of server.Start (nil on graceful shutdown, or an error)
		serverExited <- err
	}()

	// Wait for either the 'done' signal or the server to exit on its own
	select {
	case <-done:
		t.Logf("Worker %d: Received done signal. Attempting to trigger server shutdown by sending OS Interrupt signal.\n", id)
		// Get current process
		p, findProcessErr := os.FindProcess(os.Getpid())
		if findProcessErr != nil {
			// This should ideally not happen for the current process
			t.Logf("Worker %d: Failed to find current process to send signal: %v. Server might not shut down cleanly.\n", id, findProcessErr)
		} else {
			// Send SIGINT (os.Interrupt) to the current process.
			// server.Start with WithWaitForShutdownSignal should handle this.
			t.Logf("Worker %d: Sending os.Interrupt to process %d.\n", id, os.Getpid())
			if signalErr := p.Signal(os.Interrupt); signalErr != nil {
				t.Logf("Worker %d: Failed to send interrupt signal: %v. Server might not shut down cleanly.\n", id, signalErr)
			} else {
				t.Logf("Worker %d: Interrupt signal sent to process %d.\n", id, os.Getpid())
			}
		}

		// Now wait for the server.Start goroutine to complete.
		serverErr := <-serverExited
		if errors.Is(serverErr, http.ErrServerClosed) {
			t.Logf("Worker %d: Server exited with error after done signal: %v\n", id, serverErr)
		} else {
			t.Logf("Worker %d: Server shut down gracefully after done signal.\n", id)
		}
	case err := <-serverExited:
		// Server exited on its own (e.g., startup error, or normal shutdown via OS signal before 'done')
		if errors.Is(err, http.ErrServerClosed) {
			// If server.Start returns an immediate error (e.g., port in use),
			// it will come through here.
			t.Logf("Worker %d: Server exited with error: %v\n", id, err)
		} else {
			t.Logf("Worker %d: Server shut down.\n", id)
		}
	}
	t.Logf("Worker %d: Finished.\n", id)
}

func setupServer(t *testing.T) (chan struct{}, *sync.WaitGroup) {
	t.Chdir(workspaceFolderAbsPath)
	t.Logf("Changed working directory to: %s", workspaceFolderAbsPath)

	configFile, err := makeConfigFile(workspaceFolderAbsPath)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	var wg sync.WaitGroup // To wait for our goroutine to finish

	// Create a channel to signal the goroutine to stop
	// A channel of struct{} is often used because struct{} takes no memory.
	done := make(chan struct{})

	// We need to tell the WaitGroup that we are starting one goroutine
	wg.Add(1)
	go backgroundPlatformServer(t, 1, &wg, configFile, done)

	t.Logf("Sleeping for %v to allow server to start...", startupDelay)
	time.Sleep(startupDelay)

	return done, &wg
}

/*
NOTE: These tests require that the docker infrastructure is running.

Be sure to start docker services before running these tests:

	docker-compose -f docker-compose.yaml up
*/
func TestTRSIntegration(t *testing.T) {
	done, wg := setupServer(t) // Start the platform

	// Register cleanup to happen after this test and all its subtests
	t.Cleanup(func() {
		t.Logf("Cleaning up - signaling worker to stop...")
		close(done)

		t.Logf("Waiting for worker to finish...")
		wg.Wait()

		t.Logf("Worker finished.")
	})

	// Use subtests for different endpoints
	t.Run("Hello endpoint", func(t *testing.T) {
		testName := "world"
		url := fmt.Sprintf("%s/trs/hello/%s", platformEndpointWithProtocol, testName)

		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		expectedResponse := "Hello " + testName
		assert.Equal(t, expectedResponse, string(body))
	})

	t.Run("Goodbye endpoint", func(t *testing.T) {
		testName := "tester"
		url := fmt.Sprintf("%s/trs/goodbye/%s", platformEndpointWithProtocol, testName)

		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		expectedResponse := fmt.Sprintf("goodbye %s from custom handler!", testName)
		assert.Equal(t, expectedResponse, string(body))
	})

	t.Run("Encrypt endpoint", func(t *testing.T) {
		testName := "secretdata"
		url := fmt.Sprintf("%s/trs/encrypt/%s", platformEndpointWithProtocol, testName)

		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Since encryption makes binary data, just check status code and headers
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
		assert.Equal(t, "attachment; filename=\"encrypted.zip\"", resp.Header.Get("Content-Disposition"))

		// Just verify we got some data back
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}
		assert.NotEmpty(t, body, "Expected non-empty response body")
	})

	// No manual cleanup needed here - t.Cleanup handles it
}
