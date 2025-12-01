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
	version, exists := os.LookupEnv(platformImageEnvironment)
	if !exists {
		version = platformImageEnvironmentLocalImage
	}
	platformConfigPath, err := createPlatformConfiguration(localPlatformOptions, scenarioContext.ScenarioOptions, version == debugVersion)
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
		scenarioContext.RegisterShutdownHook(func() error {
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

		// Wait for platform to be ready
		logger.Debug("waiting for platform to start")
		if err := waitForPlatform(platformEndpoint); err != nil {
			return ctx, err
		}

		scenarioContext.RegisterShutdownHook(func() error {
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

func (s *LocalPlatformStepDefinitions) aEmptyLocalPlatform(ctx context.Context) (context.Context, error) {
	kt := template.Must(template.New("kc").Parse(keycloakBaseTemplate))
	return s.commonLocalPlatform(ctx, &platformStartOptions{kcProvisionPath: kt})
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
func createPlatformConfiguration(options *LocalDevOptions, scenarioOptions *LocalDevScenarioOptions, devMode bool) (string, error) {
	tempFileName := path.Join(options.CukesDir, "opentdf.yaml")
	platformKeysDir := options.KeysDir
	pgHost := "localhost"
	if !devMode {
		platformKeysDir = containerKeyPath
		pgHost = options.Hostname
	}
	t := template.Must(template.New("platform").Parse(platformTemplate))
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
	ctx.Step(`^a user exists with username "([^"]*)" and email "([^"]*)" and the following attributes:$`, platformStepDefinitions.aUser)
	ctx.Step(`^a local platform with platform template "([^"]*)" and keycloak template "([^"]*)"$`, platformStepDefinitions.aLocalPlatformWithTemplates)
}
