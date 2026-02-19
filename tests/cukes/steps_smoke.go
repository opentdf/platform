package cukes

import (
	"log/slog"
	"time"

	"github.com/cucumber/godog"
)

const troubleshootingWaitTime = 5 * time.Minute

type SmokeStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
}

func (s *SmokeStepDefinitions) thePlatformGlueIsInitialized() error {
	slog.Info("dummy step executed: platform glue is initialized")
	// Optionally, you can check s.PlatformCukesContext state or just return nil
	return nil
}

func RegisterSmokeStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	stepDefinitions := SmokeStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^the platform glue is initialized$`, stepDefinitions.thePlatformGlueIsInitialized)
	ctx.Step(`^I wait for 5 minutes$`, func() error {
		slog.Info("waiting for 5 minutes for troubleshooting...")
		time.Sleep(troubleshootingWaitTime)
		return nil
	})
}
