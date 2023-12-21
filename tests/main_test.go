package tests

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/opentdf/opentdf-v2-poc/cmd"
	"github.com/opentdf/opentdf-v2-poc/internal/config"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	conf := &config.Config{}

	if err := defaults.Set(conf); err != nil {
		slog.Error("could not set defaults", slog.String("error", err.Error()))
		os.Exit(1)
	}

	/*
		For podman
		export TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED=true; # needed to run Reaper (alternative disable it TESTCONTAINERS_RYUK_DISABLED=true)
		export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock; # needed to apply the bind with statfs
	*/

	var providerType tc.ProviderType

	if os.Getenv("TESTCONTAINERS_PODMAN") == "true" {
		providerType = tc.ProviderPodman
	} else {
		providerType = tc.ProviderDocker
	}

	req := tc.GenericContainerRequest{
		ProviderType: providerType,
		ContainerRequest: tc.ContainerRequest{
			Image:        "postgres:13.3",
			Name:         "testcontainer-postgres",
			ExposedPorts: []string{"5432/tcp"},

			Env: map[string]string{
				"POSTGRES_USER":     conf.DB.User,
				"POSTGRES_PASSWORD": conf.DB.Password,
				"POSTGRES_DB":       conf.DB.Database,
			},

			WaitingFor: wait.ForExec([]string{"pg_isready", "-h", "localhost", "-U", conf.DB.User}).WithStartupTimeout(120 * time.Second),
		},
		Started: true,
	}

	postgres, err := tc.GenericContainer(context.Background(), req)
	if err != nil {
		slog.Error("could not start postgres container", slog.String("error", err.Error()))
		panic(err)
	}

	// Cleanup the container
	defer func() {
		if err := postgres.Terminate(ctx); err != nil {
			slog.Error("could not stop postgres container", slog.String("error", err.Error()))
			return
		}

		if err := recover(); err != nil {
			os.Exit(1)
		}
	}()

	port, err := postgres.MappedPort(ctx, "5432/tcp")
	if err != nil {
		slog.Error("could not get postgres mapped port", slog.String("error", err.Error()))
		panic(err)
	}

	conf.DB.Port = port.Int()

	dbClient, err := db.NewClient(conf.DB)
	if err != nil {
		slog.Error("issue creating database client", slog.String("error", err.Error()))
		panic(err)
	}

	applied, err := dbClient.RunMigrations()
	if err != nil {
		slog.Error("issue running migrations", slog.String("error", err.Error()))
		panic(err)
	}

	slog.Info("applied migrations", slog.Int("count", applied))

	otdf := server.NewOpenTDFServer(conf.Server)
	defer otdf.Stop()

	slog.Info("starting opa engine")
	// Start the opa engine
	conf.OPA.Embedded = true
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		slog.Error("could not start opa engine", slog.String("error", err.Error()))
		panic(err)
	}
	defer eng.Stop(context.Background())

	// Register the services
	err = cmd.RegisterServices(*conf, otdf, dbClient, eng)
	if err != nil {
		slog.Error("issue registering services", slog.String("error", err.Error()))
		panic(err)
	}

	// Start the server
	slog.Info("starting opentdf server", slog.Int("grpcPort", conf.Server.Grpc.Port), slog.Int("httpPort", conf.Server.HTTP.Port))
	otdf.Run()

	m.Run()
}
