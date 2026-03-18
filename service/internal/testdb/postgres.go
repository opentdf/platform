package testdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	ProviderContainer = "container"
	envProvider       = "OPENTDF_TEST_DB_PROVIDER"

	defaultContainerStartupTimeout = 60 * time.Second
)

var ErrContainerUnavailable = errors.New("testdb: postgres container unavailable")

type PostgresConfig struct {
	User string
	//nolint:gosec // test-only config
	Password string
	Database string
	Provider string
}

type PostgresInstance struct {
	Host string
	Port int
	User string
	//nolint:gosec // test-only config
	Password string
	Database string
	Provider string
	stop     func(context.Context) error
}

func (p *PostgresInstance) Stop(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if p.stop == nil {
		return nil
	}
	return p.stop(ctx)
}

func StartPostgres(ctx context.Context, cfg PostgresConfig) (*PostgresInstance, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(os.Getenv(envProvider)))
	}
	if provider == "" {
		provider = ProviderContainer
	}
	if provider != ProviderContainer {
		return nil, fmt.Errorf("unsupported postgres test provider %q: only %q is supported", provider, ProviderContainer)
	}

	return startContainer(ctx, cfg)
}

func startContainer(ctx context.Context, cfg PostgresConfig) (*PostgresInstance, error) {
	var providerType tc.ProviderType
	if os.Getenv("TESTCONTAINERS_PODMAN") == "true" {
		providerType = tc.ProviderPodman
	} else {
		providerType = tc.ProviderDocker
	}

	containerName := "testcontainer-postgres-" + uuid.NewString()[:8]
	req := tc.GenericContainerRequest{
		ProviderType: providerType,
		ContainerRequest: tc.ContainerRequest{
			Image:        "postgres:15-alpine",
			Name:         containerName,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     cfg.User,
				"POSTGRES_PASSWORD": cfg.Password,
				"POSTGRES_DB":       cfg.Database,
			},
			WaitingFor: wait.ForSQL(nat.Port("5432/tcp"), "pgx", func(host string, port nat.Port) string {
				return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
					cfg.User,
					cfg.Password,
					net.JoinHostPort(host, port.Port()),
					cfg.Database,
				)
			}).WithStartupTimeout(defaultContainerStartupTimeout).WithQuery("SELECT 1"),
		},
		Started: true,
	}

	//nolint:sloglint // emoji
	slog.Info("📀 starting postgres container")
	postgres, err := tc.GenericContainer(ctx, req)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "docker") {
			return nil, fmt.Errorf("%w: %s", ErrContainerUnavailable, err.Error())
		}
		return nil, err
	}

	host, err := postgres.Host(ctx)
	if err != nil {
		_ = postgres.Terminate(ctx)
		return nil, fmt.Errorf("failed to get postgres container host: %w", err)
	}

	port, err := postgres.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = postgres.Terminate(ctx)
		return nil, fmt.Errorf("failed to get postgres container port: %w", err)
	}

	stop := func(ctx context.Context) error {
		return postgres.Terminate(ctx)
	}

	return &PostgresInstance{
		Host:     host,
		Port:     port.Int(),
		User:     cfg.User,
		Password: cfg.Password,
		Database: cfg.Database,
		Provider: ProviderContainer,
		stop:     stop,
	}, nil
}
