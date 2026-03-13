package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/test/fixtures"
)

func provisionFixtures(args []string) {
	fs := flag.NewFlagSet("provision fixtures", flag.ExitOnError)
	configFile := fs.String("config-file", "", "custom configuration file location")
	configKey := fs.String("config-key", "opentdf", "configuration key name")
	fixtureFile := fs.String("fixtures", "./fixtures/policy_fixtures.yaml", "path to policy_fixtures.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	ctx := context.Background()

	legacyLoader, err := config.NewLegacyLoader(*configKey, *configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load config: %v\n", err)
		os.Exit(1)
	}
	defaultSettingsLoader, err := config.NewDefaultSettingsLoader()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load config: %v\n", err)
		os.Exit(1)
	}
	cfg, err := config.Load(ctx, legacyLoader, defaultSettingsLoader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load config: %v\n", err)
		os.Exit(1)
	}

	dbClient, err := db.New(ctx, cfg.DB, cfg.Logger, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue creating database client: %v\n", err)
		os.Exit(1)
	}
	defer dbClient.Close()

	// update the schema
	cfg.DB.Schema += "_policy"

	dbI := fixtures.NewDBInterface(ctx, *cfg)
	f := fixtures.NewFixture(dbI)
	fixtures.LoadFixtureData(*fixtureFile)
	f.Provision(ctx)

	fmt.Fprintln(os.Stdout, "fixtures provision fully applied")
}
