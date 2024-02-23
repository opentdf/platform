package cmd

import (
	"fmt"

	"github.com/opentdf/platform/internal/config"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	kasdb "github.com/opentdf/platform/services/kasregistry/db"
	policydb "github.com/opentdf/platform/services/policy/db"
	"github.com/spf13/cobra"
)

var (
	provisionCmd = &cobra.Command{
		Use:   "provision",
		Short: "Run local provision of fixtures data (migrates to latest)",
	}

	provisionFixturesCmd = &cobra.Command{
		Use:   "fixtures",
		Short: "Run local provision of fixtures data",
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := config.LoadConfig()
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			ctx := cmd.Context()

			// Lets make sure we can establish a new db client
			dbClient, err := createDatabaseClient(ctx, conf.DB)
			if err != nil {
				panic(fmt.Errorf("issue creating database client: %w", err))
			}
			defer dbClient.Close()

			provisionFixtures(dbClient)
			fmt.Print("fixtures provision fully applied")
		},
	}
)

func provisionFixtures(db *db.Client) {
	dbI := fixtures.DBInterface{
		Client:       db,
		PolicyClient: policydb.NewClient(*db),
		KASRClient:   kasdb.NewClient(*db),
		Schema:       "opentdf",
	}
	f := fixtures.NewFixture(dbI)
	fixtures.LoadFixtureData("integration/fixtures.yaml")
	f.Provision()
}

func init() {
	provisionCmd.AddCommand(provisionFixturesCmd)
	rootCmd.AddCommand(provisionCmd)
}
