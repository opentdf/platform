package cmd

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/spf13/cobra"
)

var (
	provisionCmd = &cobra.Command{
		Use:   "provision",
		Short: "Run local provision of fixtures data (migrates to latest)",
	}

	provisionFixturesCmd = &cobra.Command{
		Use:   "fixtures",
		Short: "Run local provision of fixtures data (migrates to latest)",
		Long: `
** Local Development and Testing Only **

1. Open your 'docker-compose.yaml'
2. Change the 'opentdf.environment.POSTGRES_DB' from 'opentdf' to another value of your choosing (e.g. 'opentdf_local')
3. Open your root-level 'opentdf.yaml' config
4. Change the config so the 'db.database' key matches the value of the docker-compose 'POSTGRES_DB' (step 2)
5. Run 'docker-compose up' to start the connection to the new database
6. Run this command to provision the fixtures data

This command will run the local provision of fixtures data. This will migrate the database to the
latest version and provision the fixtures. To avoid any pollution of your local database, it is recommended
to run this command in a clean database. This command is intended for local development and testing purposes only.

** Teardown or Issues **
You can clear/recycle your database with 'docker-compose down' and 'docker-compose up' to start fresh.`,
		Run: func(cmd *cobra.Command, _ []string) {
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)
			cfg, err := config.LoadConfig(configKey, configFile)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			dbClient, err := db.New(context.Background(), cfg.DB)
			if err != nil {
				panic(fmt.Errorf("issue creating database client: %w", err))
			}
			defer dbClient.Close()

			// update the schema
			cfg.DB.Schema += "_policy"

			dbI := fixtures.NewDBInterface(*cfg)
			f := fixtures.NewFixture(dbI)
			fixtures.LoadFixtureData("./service/internal/fixtures/policy_fixtures.yaml")
			f.Provision()

			cmd.Print("fixtures provision fully applied\n")
		},
	}
)

func init() {
	provisionCmd.AddCommand(provisionFixturesCmd)
	rootCmd.AddCommand(provisionCmd)
}
