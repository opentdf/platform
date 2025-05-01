package integration

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/opentdf/platform/service/internal/fixtures"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
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
			Image:        "postgres:15-alpine",
			Name:         "testcontainer-postgres",
			ExposedPorts: []string{"5432/tcp"},
			HostConfigModifier: func(config *container.HostConfig) {
				config.PortBindings = nat.PortMap{
					"5432/tcp": []nat.PortBinding{
						{
							HostIP:   "0.0.0.0",
							HostPort: "54322",
						},
					},
				}
			},
			Env: map[string]string{
				"POSTGRES_USER":     conf.DB.User,
				"POSTGRES_PASSWORD": conf.DB.Password,
				"POSTGRES_DB":       conf.DB.Database,
			},

			WaitingFor: wait.ForSQL(nat.Port("5432/tcp"), "pgx", func(host string, port nat.Port) string {
				net.JoinHostPort(host, port.Port())
				return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
					conf.DB.User,
					conf.DB.Password,
					net.JoinHostPort(host, port.Port()),
					conf.DB.Database,
				)
			}).WithStartupTimeout(time.Second * 5).WithQuery("SELECT 10"),
		},
		Started: true,
	}

	slog.Info("📀 starting postgres container")
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

	slog.Info("🏠 loading fixtures")
	fixtures.LoadFixtureData("../internal/fixtures/policy_fixtures.yaml")

	m.Run()
}
