// Use the shared LoadKeycloakData from the CLI package

package cukes

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"text/template"
	"time"

	"github.com/cucumber/godog"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opentdf/platform/lib/fixtures"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/cmd"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/server"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"gopkg.in/yaml.v2"
)

const (
	containerKeyPath                   = "/app/keys"
	debugVersion                       = "DEBUG"
	platformImageEnvironment           = "PLATFORM_IMAGE"
	platformImageEnvironmentLocalImage = "platform-cukes:latest"
	userContextKey                     = "platform_users"

	// Policy-fixture DB pool defaults (mirror service/pkg/db.Config struct-tag defaults).
	policyDBConnectTimeoutSeconds    = 15
	policyDBMaxConns                 = 4
	policyDBMaxConnLifetimeSeconds   = 3600
	policyDBMaxConnIdleSeconds       = 1800
	policyDBHealthCheckPeriodSeconds = 60
)

//go:embed resources/platform.template
var platformTemplate string

//go:embed resources/platform_compose.template
var platformComposeTemplate string

//go:embed resources/keycloak_base.template
var keycloakBaseTemplate string

type LocalPlatformStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
}

type platformStartOptions struct {
	platformProvisionPath *string
	kcProvisionPath       *template.Template
	// policyProvisionPath controls policy fixture provisioning:
	//   nil        -> no policy is provisioned (default; mirrors `an empty local platform`)
	//   empty ""   -> load tests-bdd/cukes/resources/policy_default.yaml
	//   non-empty  -> load the given path; absolute, or relative to ProjectDir.
	policyProvisionPath *string
}

func (s *LocalPlatformStepDefinitions) aUser(ctx context.Context, username string, email string, attributes *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	var users []map[string]any
	attributeMap := map[string]any{}
	cellMap := map[string]int{}
	for ri, row := range attributes.Rows {
		if ri == 0 {
			for ci, c := range row.Cells {
				cellMap[c.Value] = ci
			}
		} else {
			key := row.Cells[cellMap["name"]].Value
			value := row.Cells[cellMap["value"]].Value
			var attributeAny interface{}
			jsonErr := json.Unmarshal([]byte(value), &attributeAny)
			if jsonErr != nil {
				attributeMap[key] = value
			} else {
				attributeMap[key] = attributeAny
			}
		}
	}
	userObj := scenarioContext.GetObject(userContextKey)
	if userObj != nil {
		usersObj, ok := scenarioContext.GetObject(userContextKey).([]map[string]any)
		if !ok {
			return ctx, errors.New("invalid user object")
		}
		users = usersObj
	} else {
		users = []map[string]any{}
	}
	user := map[string]any{
		"username":  username,
		"enabled":   true,
		"firstName": "fn",
		"lastName":  "ln",
		"email":     email,
		"credentials": []map[string]any{
			{
				"value": "testuser123",
				"type":  "password",
			},
		},
		"attributes": attributeMap,
		"realmRoles": []string{"opentdf-standard"},
	}
	users = append(users, user)
	scenarioContext.RecordObject(userContextKey, users)
	return ctx, nil
}

func (s *LocalPlatformStepDefinitions) commonLocalPlatform(ctx context.Context, options *platformStartOptions) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	logger := scenarioContext.TestSuiteContext.Logger
	if !scenarioContext.FirstScenario && scenarioContext.Stateless {
		// Platform is already up (shared across @stateless scenarios), but
		// each godog scenario gets its own PlatformScenarioContext with a
		// nil SDK. Re-attach the SDK to the shared endpoint so step
		// definitions (and the Background) keep working.
		if scenarioContext.SDK == nil {
			platformSDK, err := otdf.New(
				scenarioContext.ScenarioOptions.PlatformEndpoint,
				otdf.WithInsecureSkipVerifyConn(),
				otdf.WithClientCredentials("opentdf", "secret", nil),
			)
			if err != nil {
				return ctx, err
			}
			scenarioContext.SDK = platformSDK
		}
		return ctx, nil
	}
	localPlatformGlue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
	if !ok {
		return ctx, errors.New("failed to load local platform glue")
	}
	localPlatformOptions := localPlatformGlue.Options

	logger.Debug("creating scenario scoped platform db")
	pgConfig, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://postgres:changeme@localhost:%d/%s?sslmode=prefer", localPlatformOptions.postgresPort, "postgres"))
	if err != nil {
		return ctx, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return ctx, err
	}
	defer pool.Close()
	_, err = pool.Exec(context.Background(), "CREATE DATABASE "+scenarioContext.ScenarioOptions.DatabaseName)
	if err != nil {
		return ctx, err
	}

	if err := provisionKeycloak(ctx, localPlatformOptions, scenarioContext, options); err != nil {
		return ctx, err
	}

	if options.policyProvisionPath != nil {
		if err := provisionPlatformPolicy(ctx, localPlatformOptions, scenarioContext, options); err != nil {
			return ctx, err
		}
	}
	version, exists := os.LookupEnv(platformImageEnvironment)
	if !exists {
		version = platformImageEnvironmentLocalImage
	}
	platformConfigPath, err := createPlatformConfiguration(localPlatformOptions, scenarioContext.ScenarioOptions, version == debugVersion, options.platformProvisionPath)
	if err != nil {
		return ctx, err
	}

	platformEndpoint := fmt.Sprintf("http://localhost:%d", scenarioContext.ScenarioOptions.PlatformPort)

	if version == "DEBUG" { //nolint:nestif // test code debug path
		logger.Debug("starting local inline platform for debugging. This should only be used for a single scenario")
		_, platformCancel := context.WithCancel(context.Background())
		go func() {
			defer func() {
				slog.Debug("background platform process stopped")
			}()
			_ = server.Start(
				server.WithWaitForShutdownSignal(),
				server.WithConfigFile(platformConfigPath),
				server.WithConfigKey("platform"),
			)
		}()

		// Register shutdown hook to stop the platform
		scenarioContext.RegisterPlatformShutdownHook(func() error {
			logger.Debug("shutting down inline platform")
			platformCancel()
			return nil
		})

		logger.Debug("waiting for platform to start")
		if err := waitForPlatform(platformEndpoint); err != nil {
			return ctx, err
		}
	} else {
		platformComposePath, err := createPlatformComposeConfiguration(localPlatformOptions)
		if err != nil {
			return ctx, err
		}
		var composeStackFiles tc.ComposeStackFiles = []string{platformComposePath}
		composeLoggingOption := tc.WithLogger(&DockerComposeLogger{Logger: scenarioContext.TestSuiteContext.ComposeLogger})
		platformDockerCompose, err := tc.NewDockerComposeWith(composeStackFiles, composeLoggingOption)
		if err != nil {
			return ctx, err
		}
		if err := platformDockerCompose.WithEnv(map[string]string{
			"KEYS_DIR":     localPlatformOptions.KeysDir,
			"IMAGE":        version,
			"EXPOSED_PORT": strconv.Itoa(scenarioContext.ScenarioOptions.PlatformPort),
			"CONFIG_PATH":  platformConfigPath,
			"HOSTNAME":     localPlatformOptions.Hostname,
		}).Up(ctx, tc.Wait(true)); err != nil {
			logger.Error("error standing up platform container", slog.String("error", err.Error()))
			LogComposeServices(platformDockerCompose, logger)
			_ = platformDockerCompose.Down(ctx)
			return ctx, err
		}

		attachPlatformServiceLogs(ctx, scenarioContext, platformDockerCompose)

		// Wait for platform to be ready
		logger.Debug("waiting for platform to start")
		if err := waitForPlatform(platformEndpoint); err != nil {
			return ctx, err
		}

		scenarioContext.RegisterPlatformShutdownHook(func() error {
			return platformDockerCompose.Down(ctx, tc.RemoveOrphans(true))
		})
	}

	const clientID = "opentdf"
	const clientSecret = "secret"

	platformSDK, err := otdf.New(
		scenarioContext.ScenarioOptions.PlatformEndpoint,
		otdf.WithInsecureSkipVerifyConn(),
		otdf.WithClientCredentials(clientID, clientSecret, nil),
	)
	if err != nil {
		return ctx, err
	}
	scenarioContext.SDK = platformSDK
	te, _ := platformSDK.PlatformConfiguration.TokenEndpoint()
	logger.Debug("platform configuration",
		slog.String("realm", scenarioContext.ScenarioOptions.KeycloakRealm),
		slog.String("endpoint", te))

	return ctx, nil
}

func attachPlatformServiceLogs(ctx context.Context, scenarioContext *PlatformScenarioContext, platformDockerCompose tc.ComposeStack) {
	platformLogger := scenarioContext.TestSuiteContext.PlatformLogger
	if platformLogger == nil {
		return
	}

	scenarioContext.RegisterPlatformShutdownHook(func() error {
		logCtx := context.WithoutCancel(ctx)
		platformLogger.Info("capturing platform service logs", slog.String("service", "otdf"))
		container, err := platformDockerCompose.ServiceContainer(logCtx, "otdf")
		if err != nil {
			platformLogger.Warn("failed to get platform service container for log capture", slog.String("error", err.Error()))
			return nil
		}
		LogComposeService(logCtx, container, platformLogger, "otdf")
		return nil
	})
}

func (s *LocalPlatformStepDefinitions) aEmptyLocalPlatform(ctx context.Context) (context.Context, error) {
	kt := template.Must(template.New("kc").Parse(keycloakBaseTemplate))
	return s.commonLocalPlatform(ctx, &platformStartOptions{kcProvisionPath: kt})
}

func (s *LocalPlatformStepDefinitions) aDefaultLocalPlatform(ctx context.Context) (context.Context, error) {
	kt := template.Must(template.New("kc").Parse(keycloakBaseTemplate))
	defaultPolicyPath := ""
	return s.commonLocalPlatform(ctx, &platformStartOptions{
		kcProvisionPath:     kt,
		policyProvisionPath: &defaultPolicyPath,
	})
}

func (s *LocalPlatformStepDefinitions) aLocalPlatformWithPolicy(ctx context.Context, policyPath string) (context.Context, error) {
	kt := template.Must(template.New("kc").Parse(keycloakBaseTemplate))
	return s.commonLocalPlatform(ctx, &platformStartOptions{
		kcProvisionPath:     kt,
		policyProvisionPath: &policyPath,
	})
}

// func (s *LocalPlatformStepDefinitions) aDefaultLocalPlatform(ctx context.Context) (context.Context, error) {
// 	kt := template.Must(template.New("kc").Parse(keycloakFederalTemplate))
// 	scenarioContext := GetPlatformScenarioContext(ctx)
// 	localPlatformGlue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
// 	if !ok {
// 		return ctx, errors.New("no local platform glue found")
// 	}
// 	platformProvisionPath := path.Join(localPlatformGlue.Options.ProjectDir, "samples", "defaults", "federal.yaml")
// 	return s.commonLocalPlatform(ctx, &platformStartOptions{platformProvisionPath: &platformProvisionPath, kcProvisionPath: kt})
// }

func (s *LocalPlatformStepDefinitions) aLocalPlatformWithTemplates(ctx context.Context, platformTemplate string, kcTemplate string) (context.Context, error) {
	kcTemplateBytes, err := os.ReadFile(kcTemplate)
	if err != nil {
		return ctx, err
	}
	kt := template.Must(template.New("kc").Parse(string(kcTemplateBytes)))
	return s.commonLocalPlatform(ctx, &platformStartOptions{platformProvisionPath: &platformTemplate, kcProvisionPath: kt})
}

func waitForPlatform(platformEndpoint string) error {
	tries := 0
	const maxTries = 30
	const timeout = time.Millisecond * 200
	healthEndpoint := platformEndpoint + "/healthz?service=all"
	slog.Debug("waiting for platform health check", slog.String("endpoint", healthEndpoint))
	for {
		httpClient := &http.Client{Timeout: timeout}
		resp, err := httpClient.Get(healthEndpoint) //nolint:noctx //test only health check
		tries++
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			slog.Debug("platform health check passed", slog.Int("tries", tries))
			return nil
		} else if tries > maxTries {
			if resp != nil {
				_ = resp.Body.Close()
				slog.Debug("platform health check failed",
					slog.Int("status", resp.StatusCode),
					slog.Int("tries", tries),
					slog.Any("err", err))
			} else {
				slog.Debug("platform health check failed",
					slog.Int("tries", tries),
					slog.Any("err", err))
			}
			return errors.New("timeout waiting for platform to start")
		}
		if tries%10 == 0 {
			if err != nil {
				slog.Debug("platform health check retry",
					slog.Int("tries", tries),
					slog.String("err", err.Error()))
			} else if resp != nil {
				slog.Debug("platform health check retry",
					slog.Int("tries", tries),
					slog.Int("status", resp.StatusCode))
			}
		}
		time.Sleep(time.Second)
	}
}

func provisionKeycloak(ctx context.Context, suiteOptions *LocalDevOptions, scenarioContext *PlatformScenarioContext,
	startupOptions *platformStartOptions,
) error {
	scenarioOptions := scenarioContext.ScenarioOptions
	logger := scenarioContext.TestSuiteContext.Logger
	logger.Info("provision keycloak")

	var strBuffer bytes.Buffer
	var users []map[string]any
	ctxUser := scenarioContext.GetObject(userContextKey)
	if ctxUser != nil {
		userObj, ok := ctxUser.([]map[string]any)
		if !ok {
			return errors.New("keycloak users not a []map[string]any")
		}
		users = userObj
	}
	if err := startupOptions.kcProvisionPath.Execute(&strBuffer, map[string]any{
		"hostname":      suiteOptions.Hostname,
		"kcPort":        suiteOptions.keycloakPort,
		"platformPort":  scenarioOptions.PlatformPort,
		"platformPort2": scenarioOptions.PlatformPort + 1,
		"realm":         scenarioOptions.KeycloakRealm,
	}); err != nil {
		return err
	}
	if users != nil {
		var kcData map[string]interface{}
		err := yaml.Unmarshal(strBuffer.Bytes(), &kcData)
		if err != nil {
			return err
		}
		realms, realmsOk := kcData["realms"].([]interface{})
		if !realmsOk {
			return errors.New("keycloak realms not an array")
		}
		realm, ok := realms[0].(map[interface{}]interface{})
		if !ok {
			return errors.New("keycloak realm not found in realms")
		}
		realm["users"] = users
		updatedKcData, err := yaml.Marshal(kcData)
		if err != nil {
			return err
		}
		strBuffer = *bytes.NewBuffer(updatedKcData)
	}

	tmpKcFile, err := os.CreateTemp(os.TempDir(), "keycloak.yaml")
	if err != nil {
		return err
	}
	err = os.WriteFile(tmpKcFile.Name(), strBuffer.Bytes(), os.ModeTemporary)
	if err != nil {
		return err
	}
	kcData := cmd.LoadKeycloakData(tmpKcFile.Name())
	kcBasePath := fmt.Sprintf("http://%s/auth", net.JoinHostPort(suiteOptions.Hostname, strconv.Itoa(suiteOptions.keycloakPort)))
	return fixtures.SetupCustomKeycloak(ctx, fixtures.KeycloakConnectParams{
		BasePath:         kcBasePath,
		Username:         "admin",
		Password:         "changeme",
		Realm:            "",
		AllowInsecureTLS: true,
	}, kcData)
}

// provisionPlatformPolicy loads a policy fixture YAML into the scenario's
// policy schema. The path in startupOptions.policyProvisionPath is resolved
// as follows: empty string -> tests-bdd/cukes/resources/policy_default.yaml;
// absolute path -> used verbatim; relative path -> resolved under ProjectDir.
//
// NOTE: fixtures.LoadFixtureData (in service/internal/fixtures, wrapped by
// cmd.ProvisionPolicyFixturesFromFile) mutates package-global state. BDD
// scenarios currently run serially; any future move to parallel scenarios
// must serialize calls to this function.
func provisionPlatformPolicy(ctx context.Context, suiteOptions *LocalDevOptions, scenarioContext *PlatformScenarioContext,
	startupOptions *platformStartOptions,
) error {
	scenarioLogger := scenarioContext.TestSuiteContext.Logger
	scenarioLogger.Info("provision platform policy")

	fixturePath := *startupOptions.policyProvisionPath
	switch {
	case fixturePath == "":
		fixturePath = path.Join(suiteOptions.ProjectDir, "tests-bdd", "cukes", "resources", "policy_default.yaml")
	case !path.IsAbs(fixturePath):
		fixturePath = path.Join(suiteOptions.ProjectDir, fixturePath)
	}

	cfg := &config.Config{
		DB: db.Config{
			Host:           "localhost",
			Port:           suiteOptions.postgresPort,
			Database:       scenarioContext.ScenarioOptions.DatabaseName,
			User:           "postgres",
			Password:       "changeme",
			SSLMode:        "prefer",
			Schema:         "otdf",
			ConnectTimeout: policyDBConnectTimeoutSeconds,
			Pool: db.PoolConfig{
				MaxConns:          policyDBMaxConns,
				MaxConnLifetime:   policyDBMaxConnLifetimeSeconds,
				MaxConnIdleTime:   policyDBMaxConnIdleSeconds,
				HealthCheckPeriod: policyDBHealthCheckPeriodSeconds,
			},
			RunMigrations:    true,
			VerifyConnection: true,
		},
		Logger: logger.Config{
			Level:  "info",
			Output: "stdout",
			Type:   "text",
		},
	}

	// Recover from fixture panics so we return a readable error instead of
	// aborting the entire test process on a malformed fixture.
	var provisionErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				provisionErr = fmt.Errorf("policy fixture provisioning panicked: %v", r)
			}
		}()
		cmd.ProvisionPolicyFixturesFromFile(ctx, cfg, fixturePath)
	}()
	if provisionErr != nil {
		return provisionErr
	}

	// Default fixture only: pin HIERARCHY rank for demo.com/attr/classification.
	// Fixture map iteration order is non-deterministic, so the trigger that
	// auto-populates attribute_definitions.values_order would otherwise leave
	// rank up to chance. We control the rank here from test code rather than
	// adding a behavior change to the fixtures provisioner.
	if *startupOptions.policyProvisionPath == "" {
		if err := pinDefaultClassificationHierarchy(ctx, scenarioContext); err != nil {
			return fmt.Errorf("pin classification hierarchy: %w", err)
		}
	}
	return nil
}

// pinDefaultClassificationHierarchy sets values_order on the default
// fixture's classification attribute (high -> low: secret > confidential >
// internal > public) so encrypt/decrypt scenarios get deterministic
// HIERARCHY ranking.
func pinDefaultClassificationHierarchy(ctx context.Context, scenarioContext *PlatformScenarioContext) error {
	// Hard-coded UUIDs for the demo.com/attr/classification attribute and its
	// values, mirroring policy_default.yaml. They are policy-DB primary keys,
	// not credentials.
	const (
		classificationAttrID = "a1b2c3d4-e5f6-4a7b-8c9d-000000000020"
		secretValueID        = "a1b2c3d4-e5f6-4a7b-8c9d-000000000024" //nolint:gosec // attribute-value id, not a credential
		confidentialValueID  = "a1b2c3d4-e5f6-4a7b-8c9d-000000000023" //nolint:gosec // attribute-value id, not a credential
		internalValueID      = "a1b2c3d4-e5f6-4a7b-8c9d-000000000022"
		publicValueID        = "a1b2c3d4-e5f6-4a7b-8c9d-000000000021"
	)
	localPlatformGlue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
	if !ok {
		return errors.New("failed to load local platform glue")
	}
	dsn := fmt.Sprintf(
		"postgres://postgres:changeme@%s/%s?sslmode=prefer",
		net.JoinHostPort("localhost", strconv.Itoa(localPlatformGlue.Options.postgresPort)),
		scenarioContext.ScenarioOptions.DatabaseName,
	)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	_, err = pool.Exec(ctx,
		`UPDATE otdf_policy.attribute_definitions SET values_order = $1::uuid[] WHERE id = $2`,
		[]string{secretValueID, confidentialValueID, internalValueID, publicValueID},
		classificationAttrID,
	)
	return err
}

func createPlatformComposeConfiguration(options *LocalDevOptions) (string, error) {
	tmpFile, err := os.CreateTemp(options.CukesDir, "docker_compose.yaml")
	if err != nil {
		return "", err
	}
	_, err = tmpFile.Write([]byte(platformComposeTemplate))
	if err != nil {
		return tmpFile.Name(), err
	}

	return tmpFile.Name(), nil
}

// createPlatformConfiguration generates a platform configuration from a go text template for platform option settings
func createPlatformConfiguration(options *LocalDevOptions, scenarioOptions *LocalDevScenarioOptions, devMode bool, platformTemplatePath *string) (string, error) {
	tempFileName := path.Join(options.CukesDir, "opentdf.yaml")
	platformKeysDir := options.KeysDir
	pgHost := "localhost"
	if !devMode {
		platformKeysDir = containerKeyPath
		pgHost = options.Hostname
	}
	templateSource := platformTemplate
	if platformTemplatePath != nil && *platformTemplatePath != "" {
		templateBytes, err := os.ReadFile(*platformTemplatePath)
		if err != nil {
			return tempFileName, err
		}
		templateSource = string(templateBytes)
	}
	t := template.Must(template.New("platform").Parse(templateSource))
	var strBuffer bytes.Buffer
	if err := t.Execute(&strBuffer, map[string]any{
		"hostname":        options.Hostname,
		"kcPort":          options.keycloakPort,
		"platformPort":    scenarioOptions.PlatformPort,
		"pgPort":          options.postgresPort,
		"pgDatabase":      scenarioOptions.DatabaseName,
		"pgHost":          pgHost,
		"platformKeysDir": platformKeysDir,
		"authRealm":       scenarioOptions.KeycloakRealm,
	}); err != nil {
		return tempFileName, err
	}
	err := os.WriteFile(tempFileName, strBuffer.Bytes(), os.FileMode(0o755)) //nolint:mnd // mkdir dir
	if err != nil {
		return tempFileName, err
	}

	return tempFileName, nil
}

func RegisterLocalPlatformStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	platformStepDefinitions := LocalPlatformStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^an empty local platform$`, platformStepDefinitions.aEmptyLocalPlatform)
	ctx.Step(`^a default local platform$`, platformStepDefinitions.aDefaultLocalPlatform)
	ctx.Step(`^a local platform with policy "([^"]*)"$`, platformStepDefinitions.aLocalPlatformWithPolicy)
	ctx.Step(`^a user exists with username "([^"]*)" and email "([^"]*)" and the following attributes:$`, platformStepDefinitions.aUser)
	ctx.Step(`^a local platform with platform template "([^"]*)" and keycloak template "([^"]*)"$`, platformStepDefinitions.aLocalPlatformWithTemplates)
}
