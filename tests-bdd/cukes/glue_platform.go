package cukes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/tests-bdd/cukes/utils"
	tcb "github.com/testcontainers/testcontainers-go"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
)

const StatelessTag = "@stateless"

type PlatformTestSuiteContext struct {
	PlatformGlue      *PlatformGlue
	ShutdownFunctions []func() error
	FeatureTracker    map[string]*PlatformScenarioContext
	Logger            *slog.Logger
	ComposeLogger     *slog.Logger
	HasFailures       bool // Track if any test failures occurred
}
type DockerComposeLogger struct {
	Logger *slog.Logger
}

type PlatformGlue interface {
	Setup(*PlatformTestSuiteContext) error
	Shutdown(*PlatformTestSuiteContext) error
}

type LocalDevPlatformGlue struct {
	Options *LocalDevOptions
	Context context.Context //nolint:containedctx // cukes test scenario context
}

type LocalDevOptions struct {
	Hostname     string
	CukesDir     string // temp directory for cukes test suite
	KeysDir      string // directory with opentdf keys
	ProjectDir   string // the opentdf project directory.
	postgresPort int
	keycloakPort int
}

type LocalDevScenarioOptions struct {
	PlatformEndpoint       string
	KeycloakRealm          string
	InsecureSkipVerifyConn bool
	DatabaseName           string
	PlatformPort           int
}

func (d *DockerComposeLogger) Printf(format string, v ...interface{}) {
	d.Logger.Info("docker compose log", slog.String("message", fmt.Sprintf(format, v...)))
}

func CreatePlatformCukesContext(logger *slog.Logger, composeLogger *slog.Logger) *PlatformTestSuiteContext {
	return &PlatformTestSuiteContext{
		FeatureTracker: make(map[string]*PlatformScenarioContext),
		Logger:         logger,
		ComposeLogger:  composeLogger,
	}
}

func (c *PlatformTestSuiteContext) RecordFailure() {
	c.HasFailures = true
}

func (c *PlatformTestSuiteContext) InitializeScenario(scenarioContext *godog.ScenarioContext) {
	scenarioContext.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tags := sc.Tags
		statelessFeature := false
		var platformScenarioContext *PlatformScenarioContext
		for _, tag := range tags {
			if tag.Name == StatelessTag {
				statelessFeature = true
			}
		}
		trackedScenarioContext, featureTracked := c.FeatureTracker[sc.Uri]
		_, ok := (*c.PlatformGlue).(*LocalDevPlatformGlue)
		if !ok {
			return ctx, errors.New("platform glue is not of expected type LocalDevPlatformGlue")
		}
		scenarioID := uuid.New().String()
		if !featureTracked || !statelessFeature {
			platformPort := openPort()
			platformDBName := strings.ReplaceAll("opentdf"+scenarioID, "-", "_")
			platformScenarioContext = &PlatformScenarioContext{
				ID:            scenarioID,
				FirstScenario: !featureTracked,
				Stateless:     statelessFeature,
				objects:       make(map[string]interface{}),
				ScenarioOptions: &LocalDevScenarioOptions{
					DatabaseName:           platformDBName,
					PlatformPort:           platformPort,
					KeycloakRealm:          scenarioID,
					PlatformEndpoint:       fmt.Sprintf("http://localhost:%d", platformPort),
					InsecureSkipVerifyConn: true,
				},
				TestSuiteContext: c,
			}
		} else {
			platformScenarioContext = &PlatformScenarioContext{
				ID:            scenarioID,
				FirstScenario: !featureTracked,
				Stateless:     statelessFeature,
				objects:       make(map[string]interface{}),
				ScenarioOptions: &LocalDevScenarioOptions{
					DatabaseName:           trackedScenarioContext.ScenarioOptions.DatabaseName,
					PlatformPort:           trackedScenarioContext.ScenarioOptions.PlatformPort,
					KeycloakRealm:          trackedScenarioContext.ScenarioOptions.KeycloakRealm,
					PlatformEndpoint:       trackedScenarioContext.ScenarioOptions.PlatformEndpoint,
					InsecureSkipVerifyConn: trackedScenarioContext.ScenarioOptions.InsecureSkipVerifyConn,
				},
				TestSuiteContext: c,
			}
		}

		c.FeatureTracker[sc.Uri] = platformScenarioContext
		return context.WithValue(ctx, platformScenarioContextKey{}, platformScenarioContext), nil
	})
	scenarioContext.After(func(ctx context.Context, _ *godog.Scenario, err error) (context.Context, error) {
		// Record if this scenario failed
		if err != nil {
			c.RecordFailure()
		}

		shutdownHooks := GetPlatformScenarioContext(ctx).ShutdownHooks
		for _, hook := range shutdownHooks {
			hookErr := hook()
			if hookErr != nil {
				fmt.Printf("error scenario shutdownhook %v\n", hookErr) //nolint:forbidigo // testing code
			}
		}
		return ctx, nil
	})
}

func (c *PlatformTestSuiteContext) InitializeTestSuite(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		options, err := NewLocalDevOptions()
		if err != nil {
			panic(err)
		}
		var platformGlue PlatformGlue = NewLocalDevPlatformGlue(options)
		c.PlatformGlue = &platformGlue
		// todo put back
		if err := platformGlue.Setup(c); err != nil {
			panic(err)
		}
	})
	ctx.AfterSuite(func() {
		for _, sf := range c.ShutdownFunctions {
			if err := sf(); err != nil {
				fmt.Printf("error sending shutdown function: %v\n", err) //nolint:forbidigo // testing code
			}
		}
		err := (*c.PlatformGlue).Shutdown(c)
		if err != nil {
			fmt.Printf("error platform glue shutdown function: %v\n", err) //nolint:forbidigo // testing code
		}
	})
}

type PlatformScenarioContext struct {
	SDK              *otdf.SDK
	ID               string
	ScenarioOptions  *LocalDevScenarioOptions
	TestSuiteContext *PlatformTestSuiteContext
	FirstScenario    bool
	Stateless        bool
	Scenario         *godog.Scenario
	objects          map[string]interface{}
	err              error
	ShutdownHooks    []func() error
}

func (c *PlatformScenarioContext) RegisterShutdownHook(hook func() error) {
	c.ShutdownHooks = append(c.ShutdownHooks, hook)
}

func (c *PlatformScenarioContext) ClearError() {
	c.err = nil
}

func (c *PlatformScenarioContext) SetError(err error) {
	if err != nil {
		fmt.Println(err.Error()) //nolint:forbidigo // testing code
	}
	c.err = err
}

func (c *PlatformScenarioContext) GetError() error {
	return c.err
}

func (c *PlatformScenarioContext) RecordObject(key string, obj any) {
	c.objects[key] = obj
}

func (c *PlatformScenarioContext) GetObject(key string) any {
	resp, ok := c.objects[key]
	if ok {
		return resp
	}
	return nil
}

func (c *PlatformScenarioContext) GetAttributeValue(ctx context.Context, fqn string) (*policy.Value, error) {
	resp, err := c.SDK.Attributes.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{Fqns: []string{fqn}})
	if err != nil {
		return nil, err
	}
	if resp.GetFqnAttributeValues() == nil {
		return nil, fmt.Errorf("no attribute value for %s", fqn)
	}
	fqna, ok := resp.GetFqnAttributeValues()[fqn]
	if !ok {
		return nil, fmt.Errorf("no attribute value for %s", fqn)
	}
	return fqna.GetValue(), nil
}

// contextKey is the key used to store Platform Cukes Context in a context
type (
	contextKey                 struct{}
	platformScenarioContextKey struct{}
)

type PlatformCukesHelper interface {
	*context.Context
}

// NewPlatformCukesContext creates a context with a PlatformTestSuiteContext struct value using the contextKey
func NewPlatformCukesContext(cukesContext PlatformTestSuiteContext) context.Context {
	return context.WithValue(context.Background(), contextKey{}, cukesContext)
}

func GetPlatformScenarioContext(ctx context.Context) *PlatformScenarioContext {
	psc, ok := ctx.Value(platformScenarioContextKey{}).(*PlatformScenarioContext)
	if !ok {
		panic(errors.New("platform scenario context not found"))
	}
	return psc
}

func GetProjectDir() (string, error) {
	projectDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(projectDir, "tests-bdd") {
		projectDir = strings.TrimSuffix(projectDir, "tests-bdd")
		projectDir = projectDir[0:(len(projectDir) - 1)]
	}
	return projectDir, nil
}

func NewLocalDevOptions() (LocalDevOptions, error) {
	wd, err := os.Getwd()
	if err != nil {
		return LocalDevOptions{}, err
	}
	dname, err := os.MkdirTemp(wd, "cukes")
	if err != nil {
		return LocalDevOptions{}, err
	}
	keydir := path.Join(dname, "keys")
	err = os.Mkdir(keydir, os.ModePerm)
	if err != nil {
		return LocalDevOptions{}, err
	}

	projectDir, err := GetProjectDir()
	if err != nil {
		return LocalDevOptions{}, err
	}
	return LocalDevOptions{
		Hostname:   "localhost",
		CukesDir:   dname,
		KeysDir:    keydir,
		ProjectDir: projectDir,
	}, nil
}

func NewLocalDevPlatformGlue(options LocalDevOptions) *LocalDevPlatformGlue {
	return &LocalDevPlatformGlue{
		Options: &options,
		Context: context.Background(),
	}
}

func (l *LocalDevPlatformGlue) Shutdown(platformCukesContext *PlatformTestSuiteContext) error {
	// Only clean up if no failures occurred and CUKES_PRESERVE_TEST_DIRECTORY is not set
	// Environment variable CUKES_PRESERVE_TEST_DIRECTORY=true can be used to always preserve the directory
	preserveTestDirectory := os.Getenv("CUKES_PRESERVE_TEST_DIRECTORY") == "true"

	if platformCukesContext.HasFailures || preserveTestDirectory {
		platformCukesContext.Logger.Warn("preserving cukes directory for debugging",
			slog.String("directory", l.Options.CukesDir),
			slog.Bool("hasFailures", platformCukesContext.HasFailures),
			slog.Bool("preserveOnFailure", preserveTestDirectory))
		return nil
	}

	platformCukesContext.Logger.Info("cleaning up cukes directory", slog.String("directory", l.Options.CukesDir))
	err := os.RemoveAll(l.Options.CukesDir)
	return err
}

func changePermissions(dirPath string, mode os.FileMode) error {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			err = os.Chmod(path, mode)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// Setup local platform including cert/key generation and platform and keycloak configuration setup.
func (l *LocalDevPlatformGlue) Setup(platformCukesContext *PlatformTestSuiteContext) error {
	ctx := l.Context
	logger := platformCukesContext.Logger
	logger.Info("setting up local dev platform")
	logger.Info("setup mkcert")
	if err := l.mkCert(); err != nil {
		return err
	}
	logger.Info("setup temp keys")
	utils.GenerateTempKeys(l.Options.KeysDir)
	err := changePermissions(l.Options.CukesDir, os.FileMode(0o755)) //nolint:mnd // mkdir dir ensure all files are readable by docker
	if err != nil {
		return err
	}
	// random open ports to expose
	l.Options.keycloakPort = openPort()
	l.Options.postgresPort = openPort()

	logger.Info("starting with ports",
		slog.Int("keycloak_port", l.Options.keycloakPort),
		slog.Int("postgres_port", l.Options.postgresPort),
		slog.String("project_dir", l.Options.ProjectDir))

	// startup infrastructure services
	var composeStackFiles tc.ComposeStackFiles = []string{path.Join(l.Options.ProjectDir, "docker-compose.yaml")}
	composeLoggingOption := tc.WithLogger(&DockerComposeLogger{Logger: platformCukesContext.ComposeLogger})

	compose, err := tc.NewDockerComposeWith(composeStackFiles, composeLoggingOption)
	if err != nil {
		return err
	}

	//nolint:nestif // refactor later - compose is private *dockercompose
	if err := compose.WithEnv(map[string]string{
		"POSTGRES_EXPOSE_PORT": strconv.Itoa(l.Options.postgresPort),
		"KC_EXPOSE_PORT_HTTP":  strconv.Itoa(l.Options.keycloakPort), // Use HTTP port for BDD tests
		"KEYS_DIR":             l.Options.KeysDir,
		"JAVA_OPTS_APPEND":     os.Getenv("JAVA_OPTS_APPEND"), // Pass through JAVA_OPTS_APPEND for Apple Silicon compatibility
	}).Up(ctx, tc.Wait(true)); err != nil {
		logger.Error("error standing up containers", slog.String("error", err.Error()))
		// log key data
		err := filepath.WalkDir(l.Options.KeysDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, ".pem") {
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				logger.Warn("keys content",
					slog.String("path", path),
					slog.String("content", string(content)))
			}
			return nil
		})
		if err != nil {
			logger.Error("error dumping keys", slog.String("error", err.Error()))
		}
		LogComposeServices(compose, logger)
		_ = compose.Down(ctx)
		return err
	}
	platformCukesContext.ShutdownFunctions = append(platformCukesContext.ShutdownFunctions, func() error {
		return compose.Down(ctx, tc.RemoveOrphans(true))
	})
	return nil
}

func (l *LocalDevPlatformGlue) mkCert() error {
	cmd := exec.Command("mkcert", "-install") //nolint:noctx // test code
	cmd.Dir = l.Options.CukesDir
	if err := cmd.Run(); err != nil {
		return err
	}
	//nolint:gosec // G204
	cmd = exec.Command("mkcert", "-cert-file", //nolint:noctx // test code
		path.Join(l.Options.KeysDir, l.Options.Hostname+".crt"), "-key-file",
		path.Join(l.Options.KeysDir, l.Options.Hostname+".key"), l.Options.Hostname,
		"*."+l.Options.Hostname,
		"localhost")
	cmd.Dir = l.Options.CukesDir
	return cmd.Run()
}

// LogComposeService logs to `logger` all log statements for a docker container
func LogComposeService(ctx context.Context, container *tcb.DockerContainer, logger *slog.Logger, svc string) {
	logReader, composeError := container.Logs(ctx)
	if composeError != nil {
		logger.Error("error reading container logs",
			slog.String("service", svc),
			slog.String("error", composeError.Error()))
	} else {
		logBytes, err := io.ReadAll(logReader)
		if err == nil {
			logger.Warn("logs for service", slog.String("service", svc))
			for _, line := range strings.Split(string(logBytes), "\n") {
				logger.Warn("container log line",
					slog.String("service", svc),
					slog.String("line", line))
			}
		} else {
			logger.Error("error reading container logs",
				slog.String("service", svc),
				slog.String("error", err.Error()))
		}
	}
}

// LogComposeServices logs to `logger` all log statements for each service within the DockerStack instance 'c'
func LogComposeServices(c interface{}, logger *slog.Logger) {
	if c != nil {
		ctx := context.Background()
		composeStack, ok := c.(tc.ComposeStack)
		if !ok {
			logger.Error("error getting compose stack, can't cast to tc.ComposeStack")
			return
		}
		services := composeStack.Services()
		for _, svc := range services {
			container, composeError := composeStack.ServiceContainer(ctx, svc)
			if composeError != nil {
				logger.Error("error creating container for service",
					slog.String("service", svc),
					slog.String("error", composeError.Error()))
				continue
			}
			LogComposeService(ctx, container, logger, svc)
		}
	} else {
		logger.Error("compose stack is nil")
	}
}

func openPort() int {
	//nolint:gosec // G102
	listener, err := net.Listen("tcp", ":0") //nolint:noctx // test code
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	// Get the port number from the listener address
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		panic(errors.New("address is not a TCP Address"))
	}
	return tcpAddr.Port
}
