package cukes

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/cucumber/godog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type LDAPStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
}

func (s *LDAPStepDefinitions) anLDAPDirectoryWithTestUsers(ctx context.Context) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	logger := scenarioContext.TestSuiteContext.Logger

	// In @stateless mode, reuse the LDAP container from the first scenario
	if scenarioContext.Stateless && scenarioContext.ScenarioOptions.LDAPPort > 0 {
		logger.Info("reusing existing LDAP testcontainer", slog.Int("port", scenarioContext.ScenarioOptions.LDAPPort))
		return ctx, nil
	}

	glue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
	if !ok {
		return ctx, fmt.Errorf("platform glue is not LocalDevPlatformGlue")
	}
	projectDir := glue.Options.ProjectDir

	ldapDataDir := filepath.Join(projectDir, "service", "entityresolution", "integration", "ldap_test_data")
	ouFile := filepath.Join(ldapDataDir, "01_organizational_units.ldif")
	usersFile := filepath.Join(ldapDataDir, "02_test_users.ldif")

	logger.Info("starting LDAP testcontainer", slog.String("ldap_data_dir", ldapDataDir))

	containerRequest := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "OpenTDF Test",
			"LDAP_DOMAIN":         "opentdf.test",
			"LDAP_ADMIN_PASSWORD": "admin123",
		},
		Cmd: []string{"--copy-service"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      ouFile,
				ContainerFilePath: "/container/service/slapd/assets/config/bootstrap/ldif/custom/01_organizational_units.ldif",
				FileMode:          0o644,
			},
			{
				HostFilePath:      usersFile,
				ContainerFilePath: "/container/service/slapd/assets/config/bootstrap/ldif/custom/02_test_users.ldif",
				FileMode:          0o644,
			},
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(60 * time.Second),
	}

	ldapContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
	})
	if err != nil {
		return ctx, fmt.Errorf("failed to start LDAP container: %w", err)
	}

	host, err := ldapContainer.Host(ctx)
	if err != nil {
		return ctx, fmt.Errorf("failed to get LDAP container host: %w", err)
	}

	mappedPort, err := ldapContainer.MappedPort(ctx, "389")
	if err != nil {
		return ctx, fmt.Errorf("failed to get LDAP container port: %w", err)
	}

	scenarioContext.ScenarioOptions.LDAPPort = int(mappedPort.Num())

	logger.Info("LDAP testcontainer started",
		slog.String("host", host),
		slog.Int("port", scenarioContext.ScenarioOptions.LDAPPort))

	scenarioContext.RegisterPlatformShutdownHook(func() error {
		logger.Info("terminating LDAP testcontainer")
		return ldapContainer.Terminate(context.WithoutCancel(ctx))
	})

	return ctx, nil
}

func RegisterLDAPStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	steps := &LDAPStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^an LDAP directory with test users$`, steps.anLDAPDirectoryWithTestUsers)
}
