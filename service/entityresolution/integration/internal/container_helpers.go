package internal

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/docker/go-connections/nat"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ContainerManager provides standardized container lifecycle management
type ContainerManager struct {
	Container tc.Container
	Config    ContainerConfig
}

// ContainerConfig holds configuration for a test container
type ContainerConfig struct {
	Image        string
	ExposedPorts []string
	Env          map[string]string
	Cmd          []string
	WaitStrategy wait.Strategy
	Timeout      time.Duration
}

// NewContainerManager creates a new container manager with the given configuration
func NewContainerManager(config ContainerConfig) *ContainerManager {
	return &ContainerManager{
		Config: config,
	}
}

// Start starts the container and waits for it to be ready
func (cm *ContainerManager) Start(ctx context.Context) error {
	if cm.Container != nil {
		return fmt.Errorf("container already started")
	}

	// Set default timeout if not specified
	timeout := cm.Config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	req := tc.ContainerRequest{
		Image:        cm.Config.Image,
		ExposedPorts: cm.Config.ExposedPorts,
		Env:          cm.Config.Env,
		Cmd:          cm.Config.Cmd,
		WaitingFor:   cm.Config.WaitStrategy,
	}

	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", cm.Config.Image, err)
	}

	cm.Container = container
	return nil
}

// Stop stops and removes the container
func (cm *ContainerManager) Stop(ctx context.Context) error {
	if cm.Container == nil {
		return nil // Already stopped or never started
	}

	if err := cm.Container.Terminate(ctx); err != nil {
		// Log warning but don't fail - container might already be terminated
		slog.Warn("Failed to terminate container", "image", cm.Config.Image, "error", err.Error())
	}

	cm.Container = nil
	return nil
}

// GetMappedPort returns the host port mapped to the container port
func (cm *ContainerManager) GetMappedPort(ctx context.Context, containerPort string) (int, error) {
	if cm.Container == nil {
		return 0, fmt.Errorf("container not started")
	}

	mappedPort, err := cm.Container.MappedPort(ctx, nat.Port(containerPort))
	if err != nil {
		return 0, fmt.Errorf("failed to get mapped port for %s: %w", containerPort, err)
	}

	return mappedPort.Int(), nil
}

// GetHost returns the container host (typically localhost)
func (cm *ContainerManager) GetHost() string {
	return "localhost"
}

// IsRunning returns true if the container is currently running
func (cm *ContainerManager) IsRunning() bool {
	return cm.Container != nil
}


// ContainerTestSuite provides a standardized way to manage multiple containers for testing
type ContainerTestSuite struct {
	containers map[string]*ContainerManager
}

// NewContainerTestSuite creates a new container test suite
func NewContainerTestSuite() *ContainerTestSuite {
	return &ContainerTestSuite{
		containers: make(map[string]*ContainerManager),
	}
}

// AddContainer adds a container to the test suite
func (suite *ContainerTestSuite) AddContainer(name string, config ContainerConfig) {
	suite.containers[name] = NewContainerManager(config)
}

// StartAll starts all containers in the suite
func (suite *ContainerTestSuite) StartAll(ctx context.Context) error {
	for name, manager := range suite.containers {
		if err := manager.Start(ctx); err != nil {
			// If any container fails to start, stop all previously started containers
			suite.StopAll(ctx)
			return fmt.Errorf("failed to start container %s: %w", name, err)
		}
	}
	return nil
}

// StopAll stops all containers in the suite
func (suite *ContainerTestSuite) StopAll(ctx context.Context) error {
	var lastErr error
	for name, manager := range suite.containers {
		if err := manager.Stop(ctx); err != nil {
			slog.Warn("Failed to stop container", "name", name, "error", err.Error())
			lastErr = err
		}
	}
	return lastErr
}

// GetContainer returns a container manager by name
func (suite *ContainerTestSuite) GetContainer(name string) (*ContainerManager, bool) {
	manager, exists := suite.containers[name]
	return manager, exists
}

// GetContainerPort returns the mapped port for a container
func (suite *ContainerTestSuite) GetContainerPort(ctx context.Context, containerName, containerPort string) (int, error) {
	manager, exists := suite.containers[containerName]
	if !exists {
		return 0, fmt.Errorf("container %s not found", containerName)
	}
	return manager.GetMappedPort(ctx, containerPort)
}