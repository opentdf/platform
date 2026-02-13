package integration

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/creasty/defaults"
	"github.com/opentdf/platform/lib/fixtures"
	"github.com/opentdf/platform/tests/internal/containers"
)

const note = `
====================================================================================
 Integration Tests
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
 Test runner hanging at '📀 starting postgres container'?
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
	ctx := context.Background()
	conf := Config

	if err := defaults.Set(conf); err != nil {
		slog.Error("could not set defaults", slog.String("error", err.Error()))
		os.Exit(1)
	}

	//nolint:sloglint // emoji
	slog.Info("📀 starting postgres container")
	postgres, port, err := containers.StartPostgres(ctx, containers.PostgresConfig{
		User:     conf.DB.User,
		Password: conf.DB.Password,
		Database: conf.DB.Database,
	})
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

	conf.DB.Port = port

	//nolint:sloglint // emoji
	slog.Info("🏠 loading fixtures")
	fixtures.LoadFixtureDataFromDefault()

	m.Run()
}
