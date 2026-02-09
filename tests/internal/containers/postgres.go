package containers

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PostgresConfig struct {
	User           string
	Password       string
	Database       string
	Image          string
	ContainerName  string
	StartupTimeout time.Duration
}

func StartPostgres(ctx context.Context, cfg PostgresConfig) (tc.Container, int, error) {
	if cfg.Image == "" {
		cfg.Image = "postgres:15-alpine"
	}
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = 60 * time.Second
	}
	if cfg.ContainerName == "" {
		randomSuffix := uuid.NewString()[:8]
		cfg.ContainerName = "testcontainer-postgres-" + randomSuffix
	}

	req := tc.GenericContainerRequest{
		ProviderType: ProviderType(),
		ContainerRequest: tc.ContainerRequest{
			Image:        cfg.Image,
			Name:         cfg.ContainerName,
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
			}).WithStartupTimeout(cfg.StartupTimeout).WithQuery("SELECT 1"),
		},
		Started: true,
	}

	container, err := tc.GenericContainer(ctx, req)
	if err != nil {
		return nil, 0, err
	}

	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, 0, err
	}

	return container, port.Int(), nil
}
