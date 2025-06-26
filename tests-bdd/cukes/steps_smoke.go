package cukes

import (
	"log/slog"

	"github.com/cucumber/godog"
)

type SmokeStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
}

func (s *SmokeStepDefinitions) thePlatformGlueIsInitialized() error {
	slog.Info("Dummy step executed: platform glue is initialized")
	// Optionally, you can check s.PlatformCukesContext state or just return nil
	return nil
}

func RegisterSmokeStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	stepDefinitions := SmokeStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^the platform glue is initialized$`, stepDefinitions.thePlatformGlueIsInitialized)
}
