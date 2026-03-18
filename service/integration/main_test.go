package integration

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/internal/testdb"
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

	instance, err := testdb.StartPostgres(ctx, testdb.PostgresConfig{
		User:     conf.DB.User,
		Password: conf.DB.Password,
		Database: conf.DB.Database,
	})
	if err != nil {
		if errors.Is(err, testdb.ErrContainerUnavailable) {
			slog.Error("postgres container unavailable", slog.String("error", err.Error()))
			os.Exit(1)
		}
		slog.Error("could not start postgres for integration tests", slog.String("error", err.Error()))
		os.Exit(1)
	}

	conf.DB.Host = instance.Host
	conf.DB.Port = instance.Port

	//nolint:sloglint // emoji
	slog.Info("🏠 loading fixtures")
	fixtures.LoadFixtureData("../internal/fixtures/policy_fixtures.yaml")

	exitCode := m.Run()

	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := instance.Stop(stopCtx); err != nil {
		slog.Error("could not stop postgres", slog.String("error", err.Error()))
	}
	cancel()

	os.Exit(exitCode)
}
