//go:build cukes

package test_bdd

import (
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/opentdf/platform/tests-bdd/cukes"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
	"github.com/spf13/pflag"
)

var opts = godog.Options{
	Output: colors.Colored(os.Stdout),
	Format: "progress",
}

func init() {
	godog.BindCommandLineFlags("godog.", &opts)
}

func TestFeatures(t *testing.T) {
	status := runTests()
	if status != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

// runTest runs cukes tests with a default context = PlatformTestSuiteContext and custom test suite and scenario initializer
func runTests() int {
	pflag.Parse()

	cukesLogOption, ok := os.LookupEnv("CUKES_LOG_HANDLER")
	projectDir, err := cukes.GetProjectDir()
	if err != nil {
		slog.Error("error getting project directory", slog.String("error", err.Error()))
		return 1
	}
	var cukesIoWriter io.Writer
	if ok && strings.ToLower(cukesLogOption) == "console" {
		cukesIoWriter = os.Stdout
	} else {
		cukesLogFile, err := os.Create(path.Join(projectDir, "cukes_platform.log"))
		if err != nil {
			slog.Error("failed to cukes log file", slog.String("error", err.Error()))
			return 1
		}
		cukesIoWriter = cukesLogFile
	}
	logger := slog.New(slog.NewTextHandler(cukesIoWriter, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	composeLogOption, ok := os.LookupEnv("COMPOSE_LOG_HANDLER")
	var composeIoWriter io.Writer
	if ok && strings.ToLower(composeLogOption) == "console" {
		composeIoWriter = os.Stdout
	} else {
		composeLogFile, err := os.Create(path.Join(projectDir, "cukes_platform_compose.log"))
		if err != nil {
			logger.Error("failed to create compose log file", slog.String("error", err.Error()))
			return 1
		}
		composeIoWriter = composeLogFile
	}
	composeLogger := slog.New(slog.NewTextHandler(composeIoWriter,
		&slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	))
	slog.SetDefault(logger)

	opts.Paths = pflag.Args()
	platformCukesContext := cukes.CreatePlatformCukesContext(logger, composeLogger)
	opts.DefaultContext = cukes.NewPlatformCukesContext(*platformCukesContext)
	status := godog.TestSuite{
		Name:                 "platform",
		TestSuiteInitializer: platformCukesContext.InitializeTestSuite,
		ScenarioInitializer: func(ctx *godog.ScenarioContext) {
			cukes.RegisterLocalPlatformStepDefinitions(ctx, platformCukesContext)
			cukes.RegisterNamespaceStepDefinitions(ctx)
			cukes.RegisterAttributeStepDefinitions(ctx, platformCukesContext)
			cukes.RegisterSmokeStepDefinitions(ctx, platformCukesContext)
			platformCukesContext.InitializeScenario(ctx)
		},
		Options: &opts,
	}.Run()

	return status
}

// TestMain runs as a test suite
func TestMain(_ *testing.M) {
	status := runTests()
	os.Exit(status)
}
