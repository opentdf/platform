package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/opentdf/platform/service/logger"
)

const (
	defaultEmbeddedStartTimeout = 30 * time.Second
	defaultEmbeddedStopTimeout  = 10 * time.Second
	bundledBinariesDir          = "/opt/opentdf/embedded-postgres/binaries"
)

type EmbeddedConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// RootDir is the single mounted directory used by embedded Postgres.
	RootDir string `mapstructure:"root_dir" json:"root_dir"`
	// StartTimeoutSeconds configures how long to wait for embedded Postgres to start.
	StartTimeoutSeconds int `mapstructure:"start_timeout_seconds" json:"start_timeout_seconds" default:"30"`
	// StopTimeoutSeconds configures how long to wait for embedded Postgres to stop.
	StopTimeoutSeconds int `mapstructure:"stop_timeout_seconds" json:"stop_timeout_seconds" default:"10"`
}

type embeddedInstance struct {
	cfg         EmbeddedConfig
	dbConfig    Config
	host        string
	port        int
	layout      embeddedLayout
	instance    *embeddedpostgres.EmbeddedPostgres
	refCount    int
	stopTimeout time.Duration
	release     func(context.Context) error
}

type embeddedLayout struct {
	dataDir    string
	runtimeDir string
	cacheDir   string
}

var embeddedState struct {
	mu       sync.Mutex
	instance *embeddedInstance
}

func maybeStartEmbedded(ctx context.Context, cfg Config, log *logger.Logger) (Config, func(context.Context) error, error) {
	if !cfg.Embedded.Enabled {
		return cfg, nil, nil
	}
	if strings.TrimSpace(cfg.Host) != "" {
		return cfg, nil, nil
	}

	layout := resolveEmbeddedLayout(cfg.Embedded)
	if layout.dataDir == "" {
		return cfg, nil, errors.New("embedded postgres enabled but db.embedded.root_dir is empty")
	}

	embeddedState.mu.Lock()
	defer embeddedState.mu.Unlock()

	if embeddedState.instance != nil {
		if err := ensureEmbeddedCompatible(cfg, embeddedState.instance); err != nil {
			return cfg, nil, err
		}
		embeddedState.instance.refCount++
		updated := applyEmbeddedConnection(cfg, embeddedState.instance.host, embeddedState.instance.port)
		return updated, embeddedState.instance.release, nil
	}

	port := cfg.Port
	var err error
	if port == 0 {
		port, err = pickFreePort(ctx)
		if err != nil {
			return cfg, nil, err
		}
	}

	startTimeout := defaultEmbeddedStartTimeout
	if cfg.Embedded.StartTimeoutSeconds > 0 {
		startTimeout = time.Duration(cfg.Embedded.StartTimeoutSeconds) * time.Second
	}

	stopTimeout := defaultEmbeddedStopTimeout
	if cfg.Embedded.StopTimeoutSeconds > 0 {
		stopTimeout = time.Duration(cfg.Embedded.StopTimeoutSeconds) * time.Second
	}

	if err := ensureDir(layout.dataDir); err != nil {
		return cfg, nil, err
	}
	if layout.runtimeDir != "" {
		if err := ensureDir(layout.runtimeDir); err != nil {
			return cfg, nil, err
		}
	}
	if layout.cacheDir != "" {
		if err := ensureDir(layout.cacheDir); err != nil {
			return cfg, nil, err
		}
	}

	embeddedCfg := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V15).
		Port(uint32(port)).
		Username(cfg.User).
		Password(cfg.Password).
		Database(cfg.Database).
		DataPath(layout.dataDir).
		StartTimeout(startTimeout).
		Logger(io.Discard)

	if layout.runtimeDir != "" {
		embeddedCfg = embeddedCfg.RuntimePath(layout.runtimeDir)
	}
	if layout.cacheDir != "" {
		embeddedCfg = embeddedCfg.CachePath(layout.cacheDir)
	}
	if fileExists(filepath.Join(bundledBinariesDir, "bin", "pg_ctl")) {
		embeddedCfg = embeddedCfg.BinariesPath(bundledBinariesDir)
	}

	log.Info("starting embedded postgres", slog.Int("port", port))

	instance := embeddedpostgres.NewDatabase(embeddedCfg)
	if err := instance.Start(); err != nil {
		return cfg, nil, fmt.Errorf("failed to start embedded postgres: %w", err)
	}

	state := &embeddedInstance{
		cfg:         cfg.Embedded,
		dbConfig:    cfg,
		host:        "127.0.0.1",
		port:        port,
		layout:      layout,
		instance:    instance,
		refCount:    1,
		stopTimeout: stopTimeout,
	}
	state.release = func(ctx context.Context) error {
		return releaseEmbedded(ctx, state)
	}

	embeddedState.instance = state

	updated := applyEmbeddedConnection(cfg, state.host, state.port)
	return updated, state.release, nil
}

func applyEmbeddedConnection(cfg Config, host string, port int) Config {
	cfg.Host = host
	cfg.Port = port
	return cfg
}

func ensureEmbeddedCompatible(cfg Config, running *embeddedInstance) error {
	if running == nil {
		return nil
	}
	if cfg.User != running.dbConfig.User ||
		cfg.Password != running.dbConfig.Password ||
		cfg.Database != running.dbConfig.Database {
		return errors.New("embedded postgres already running with different database credentials")
	}

	layout := resolveEmbeddedLayout(cfg.Embedded)
	if layout.dataDir != running.layout.dataDir ||
		layout.runtimeDir != running.layout.runtimeDir ||
		layout.cacheDir != running.layout.cacheDir {
		return errors.New("embedded postgres already running with different root_dir")
	}

	if cfg.Port != 0 && cfg.Port != running.port {
		return errors.New("embedded postgres already running on a different port")
	}

	return nil
}

func releaseEmbedded(ctx context.Context, state *embeddedInstance) error {
	embeddedState.mu.Lock()
	if embeddedState.instance == nil || embeddedState.instance != state {
		embeddedState.mu.Unlock()
		return nil
	}

	embeddedState.instance.refCount--
	if embeddedState.instance.refCount > 0 {
		embeddedState.mu.Unlock()
		return nil
	}

	instance := embeddedState.instance.instance
	stopTimeout := embeddedState.instance.stopTimeout
	embeddedState.instance = nil
	embeddedState.mu.Unlock()

	stopCtx := ctx
	var cancel context.CancelFunc
	if _, ok := stopCtx.Deadline(); !ok {
		stopCtx, cancel = context.WithTimeout(stopCtx, stopTimeout)
	}
	if cancel != nil {
		defer cancel()
	}

	done := make(chan error, 1)
	go func() {
		done <- instance.Stop()
	}()

	select {
	case err := <-done:
		return err
	case <-stopCtx.Done():
		return stopCtx.Err()
	}
}

func resolveEmbeddedLayout(cfg EmbeddedConfig) embeddedLayout {
	rootDir := filepath.Clean(strings.TrimSpace(cfg.RootDir))
	if rootDir == "" {
		return embeddedLayout{}
	}

	return embeddedLayout{
		dataDir:    filepath.Join(rootDir, "data"),
		runtimeDir: filepath.Join(rootDir, "runtime"),
		cacheDir:   filepath.Join(rootDir, "cache"),
	}
}

func ensureDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("path is empty")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
