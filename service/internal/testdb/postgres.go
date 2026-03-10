package testdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-connections/nat"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	ProviderContainer = "container"
	ProviderEmbedded  = "embedded"

	envProvider     = "OPENTDF_TEST_DB_PROVIDER"
	envDataDir      = "OPENTDF_TEST_DB_DATA_DIR"
	envRuntimeDir   = "OPENTDF_TEST_DB_RUNTIME_DIR"
	envBinariesDir  = "OPENTDF_TEST_DB_BINARIES_DIR"
	envPort         = "OPENTDF_TEST_DB_PORT"
	envStartTimeout = "OPENTDF_TEST_DB_START_TIMEOUT_SECONDS"

	defaultContainerStartupTimeout = 60 * time.Second
	defaultEmbeddedStartTimeout    = 30 * time.Second
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
	cleanup  func()
}

func (p *PostgresInstance) Stop(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var err error
	if p.stop != nil {
		err = p.stop(ctx)
	}
	if p.cleanup != nil {
		p.cleanup()
	}
	return err
}

func StartPostgres(ctx context.Context, cfg PostgresConfig) (*PostgresInstance, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(os.Getenv(envProvider)))
	}
	if provider == "" {
		provider = ProviderContainer
	}

	switch provider {
	case ProviderContainer:
		return startContainer(ctx, cfg)
	case ProviderEmbedded:
		return startEmbedded(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown postgres test provider %q", provider)
	}
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

func startEmbedded(ctx context.Context, cfg PostgresConfig) (*PostgresInstance, error) {
	port, err := parsePortEnv(envPort)
	if err != nil {
		return nil, err
	}
	if port == 0 {
		port, err = pickFreePort(ctx)
		if err != nil {
			return nil, err
		}
	}

	dataDir := strings.TrimSpace(os.Getenv(envDataDir))
	runtimeDir := strings.TrimSpace(os.Getenv(envRuntimeDir))
	binariesDir := strings.TrimSpace(os.Getenv(envBinariesDir))

	var cleanup func()
	if dataDir == "" {
		baseDir, err := os.MkdirTemp("", "opentdf-embedded-postgres-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir for embedded postgres: %w", err)
		}
		dataDir = filepath.Join(baseDir, "data")
		if runtimeDir == "" {
			runtimeDir = filepath.Join(baseDir, "runtime")
		}
		cleanup = func() { _ = os.RemoveAll(baseDir) }
	} else if runtimeDir == "" {
		runtimeDir, err = os.MkdirTemp("", "opentdf-embedded-postgres-runtime-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create runtime dir for embedded postgres: %w", err)
		}
		cleanup = func() { _ = os.RemoveAll(runtimeDir) }
	}
	//nolint:gosec // test-only; allow env-provided paths
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to create embedded postgres data dir: %w", err)
	}
	//nolint:gosec // test-only; allow env-provided paths
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to create embedded postgres runtime dir: %w", err)
	}
	if binariesDir != "" {
		//nolint:gosec // test-only; allow env-provided paths
		if err := os.MkdirAll(binariesDir, 0o700); err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, fmt.Errorf("failed to create embedded postgres binaries dir: %w", err)
		}
	}

	startTimeout := defaultEmbeddedStartTimeout
	if timeoutEnv := strings.TrimSpace(os.Getenv(envStartTimeout)); timeoutEnv != "" {
		parsed, err := strconv.Atoi(timeoutEnv)
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, fmt.Errorf("invalid %s: %w", envStartTimeout, err)
		}
		startTimeout = time.Duration(parsed) * time.Second
	}

	embeddedCfg := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V15).
		Port(uint32(port)).
		Username(cfg.User).
		Password(cfg.Password).
		Database(cfg.Database).
		DataPath(dataDir).
		RuntimePath(runtimeDir).
		StartTimeout(startTimeout)
	if binariesDir != "" {
		embeddedCfg = embeddedCfg.BinariesPath(binariesDir)
	}

	postgres := embeddedpostgres.NewDatabase(embeddedCfg)

	//nolint:sloglint // emoji
	slog.Info("📦 starting embedded postgres", slog.Int("port", port))
	if err := postgres.Start(); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to start embedded postgres: %w", err)
	}

	stop := func(ctx context.Context) error {
		done := make(chan error, 1)
		go func() {
			done <- postgres.Stop()
		}()
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return &PostgresInstance{
		Host:     "127.0.0.1",
		Port:     port,
		User:     cfg.User,
		Password: cfg.Password,
		Database: cfg.Database,
		Provider: ProviderEmbedded,
		stop:     stop,
		cleanup:  cleanup,
	}, nil
}

func parsePortEnv(name string) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return port, nil
}

func pickFreePort(ctx context.Context) (int, error) {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to pick free port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("failed to resolve tcp address for listener")
	}
	return addr.Port, nil
}
